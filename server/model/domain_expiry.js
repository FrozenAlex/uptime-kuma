const net = require("node:net");
const { domainToASCII, domainToUnicode } = require("node:url");
const { BeanModel } = require("redbean-node/dist/bean-model");
const { R } = require("redbean-node");
const { log, TYPES_WITH_DOMAIN_EXPIRY_SUPPORT_VIA_FIELD } = require("../../src/util");
const { getHostname, parse: parseTld } = require("tldts");
const { setting, setSetting } = require("../util");
const { Notification } = require("../notification");
const TranslatableError = require("../translatable-error");
const dayjs = require("dayjs");
const { Settings } = require("../settings");

const tciWhoisTlds = new Set(["ru", "xn--p1ai", "su"]);
let cacheRdapDnsData = null;
let nextChecking = 0;
let running = false;

/**
 * Select the registry lookup used by both the monitor editor and expiry checks.
 * @param {string} tld Root TLD in ASCII
 * @returns {Promise<((domain: string) => Promise<Date|null>)|null>} Expiry lookup, if supported
 */
async function getDomainExpiryLookup(tld) {
    const rdapDnsData = await getRdapDnsData();
    const services = rdapDnsData["services"] ?? [];
    for (const [tlds, urls] of services) {
        if (tlds.includes(tld) && urls[0]) {
            return (domain) => getRdapDomainExpiryDate(domain, urls[0]);
        }
    }
    return tciWhoisTlds.has(tld) ? getTciDomainExpiryDate : null;
}

/**
 * Get RDAP DNS data from IANA and save to Setting
 * @returns {Promise<{}>} RDAP DNS data
 */
async function getRdapDnsData() {
    // Cache for one week
    if (cacheRdapDnsData && Date.now() < nextChecking) {
        return cacheRdapDnsData;
    }

    // Avoid multiple simultaneous updates
    // Use older data first if another update is in progress
    if (running) {
        return await getOfflineRdapDnsData();
    }

    try {
        running = true;
        log.info("rdap", "Updating RDAP DNS data from IANA...");
        const response = await fetch("https://data.iana.org/rdap/dns.json");
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();

        // Simple validation
        if (!data.services || !Array.isArray(data.services)) {
            throw new Error("Invalid RDAP DNS data structure");
        }

        cacheRdapDnsData = data;

        // Next week
        nextChecking = Date.now() + 7 * 24 * 60 * 60 * 1000;
        await Settings.set("rdapDnsData", data);
        log.info("rdap", "RDAP DNS data updated successfully. Number of services: " + data.services.length);
    } catch (error) {
        log.info("rdap", `Uable to update RDAP DNS data from source: ${error.message}`);
        cacheRdapDnsData = await getOfflineRdapDnsData();

        // Check again next day
        nextChecking = Date.now() + 24 * 60 * 60 * 1000;
    }

    running = false;
    return cacheRdapDnsData;
}

/**
 * Get RDAP DNS data from Setting or hardcoded file as fallback
 * Fail safe
 * @returns {Promise<{}>} RDAP DNS data
 */
async function getOfflineRdapDnsData() {
    let data = null;
    try {
        data = await Settings.get("rdapDnsData");

        // Simple validation
        if (!data.services || !Array.isArray(data.services)) {
            throw new Error("Invalid RDAP DNS data structure");
        }
    } catch (e) {
        // If not downloaded previously, use the hardcoded data
        data = require("../../extra/rdap-dns.json");
    }
    return data;
}

/**
 * Request RDAP server to retrieve the expiry date of a domain
 * @param {string} domain Domain to retrieve the expiry date from
 * @param {string} rdapServer Registry base URL from IANA
 * @returns {Promise<(Date|null)>} Expiry date from RDAP server
 */
async function getRdapDomainExpiryDate(domain, rdapServer) {
    const url = `${rdapServer}domain/${domain}`;

    let rdapInfos;
    try {
        const res = await fetch(url);
        if (res.status !== 200) {
            return null;
        }
        rdapInfos = await res.json();
    } catch {
        log.warn("rdap", "Not able to get expiry date from RDAP");
        return null;
    }

    if (rdapInfos["events"] === undefined) {
        return null;
    }
    for (const event of rdapInfos["events"]) {
        if (event["eventAction"] === "expiration") {
            return new Date(event["eventDate"]);
        }
    }
    return null;
}

/**
 * Read the registration deadline from the domain's TCI WHOIS record.
 * @param {string} domain Registrable ASCII domain
 * @returns {Promise<Date|null>} Registration expiry in UTC
 */
async function getTciDomainExpiryDate(domain) {
    const socket = net.createConnection({ host: "whois.tcinet.ru", port: 43, signal: AbortSignal.timeout(5000) });
    try {
        socket.write(domain + "\r\n");
        let response = "";
        for await (const chunk of socket) {
            // latin1 preserves a one-to-one mapping between bytes and characters.
            if (response.length + chunk.length > 64 * 1024) {
                return null;
            }
            response += chunk.toString("latin1");
        }
        for (const record of response.split(/\r?\n[ \t]*\r?\n/)) {
            const names = [...record.matchAll(/^domain:[ \t]*(\S+)[ \t]*$/gim)];
            if (names.length !== 1 || names[0][1].toLowerCase() !== domain) {
                continue;
            }
            const deadlines = [...record.matchAll(/^paid-till:[ \t]*(\S+)[ \t]*$/gim)];
            if (deadlines.length !== 1) {
                return null;
            }
            // Round-trip the registry's UTC timestamp to reject rolled-over dates such as February 30.
            const iso = deadlines[0][1].replace(/(T\d\d:\d\d:\d\d)Z$/, "$1.000Z");
            const expiry = new Date(iso);
            return Number.isFinite(expiry.getTime()) && expiry.toISOString() === iso ? expiry : null;
        }
    } catch (error) {
        log.debug("domain_expiry", `WHOIS lookup for ${domain} failed: ${error.message}`);
    } finally {
        socket.destroy();
    }
    return null;
}

/**
 * Send a certificate notification when domain expires in less than target days
 * @param {string} domain Domain we monitor
 * @param {number} daysRemaining Number of days remaining on certificate
 * @param {number} targetDays Number of days to alert after
 * @param {LooseObject<any>[]} notificationList List of notification providers
 * @returns {Promise<void>}
 */
async function sendDomainNotificationByTargetDays(domain, daysRemaining, targetDays, notificationList) {
    let sent = false;
    log.debug("domain_expiry", `Send domain expiry notification for ${targetDays} deadline.`);

    for (let notification of notificationList) {
        try {
            log.debug("domain_expiry", `Sending to ${notification.name}`);
            await Notification.send(
                JSON.parse(notification.config),
                `Domain name ${domain} will expire in ${daysRemaining} days`
            );
            sent = true;
        } catch (e) {
            log.error("domain_expiry", `Cannot send domain notification to ${notification.name}:`, e);
        }
    }

    return sent;
}

class DomainExpiry extends BeanModel {
    /**
     * @param {string} domain Domain name
     * @returns {Promise<DomainExpiry>} Domain bean
     */
    static async findByName(domain) {
        const ascii = domainToASCII(domain);
        const bean = await R.findOne("domain_expiry", "domain = ?", [ascii]);
        if (!bean && ascii.includes("xn--")) {
            // Older monitors could cache the Unicode spelling of an RDAP domain.
            const legacy = await R.findOne("domain_expiry", "domain = ?", [domainToUnicode(ascii)]);
            if (legacy && domainToASCII(legacy.domain) === ascii) {
                return legacy;
            }
        }
        return bean;
    }

    /**
     * @param {string} domain Domain name
     * @returns {DomainExpiry} Domain bean
     */
    static createByName(domain) {
        const d = R.dispense("domain_expiry");
        d.domain = domainToASCII(domain);
        return d;
    }

    static parseTld = parseTld;

    /**
     * @typedef {import("tldts-core").IResult} DomainComponents
     * @returns {DomainComponents} parsed domain components
     */
    parseName() {
        return parseTld(this.domain);
    }

    /**
     * @returns {(null|object)} parsed domain tld
     */
    get tld() {
        return this.parseName().publicSuffix;
    }

    /**
     * @param {Monitor} monitor Monitor object
     * @throws {TranslatableError} Throws an error if the monitor type is unsupported or missing target.
     * @returns {Promise<{ domain: string, tld: string }>} Domain expiry support info
     */
    static async checkSupport(monitor) {
        if (!(monitor.type in TYPES_WITH_DOMAIN_EXPIRY_SUPPORT_VIA_FIELD)) {
            throw new TranslatableError("domain_expiry_unsupported_monitor_type");
        }
        const targetField = TYPES_WITH_DOMAIN_EXPIRY_SUPPORT_VIA_FIELD[monitor.type];
        const target = monitor[targetField];
        if (typeof target !== "string" || target.length === 0) {
            throw new TranslatableError("domain_expiry_unsupported_missing_target");
        }

        const tld = parseTld(domainToASCII(getHostname(target) ?? ""));

        // It must be checked first, filter out non-ICANN domains.
        if (!tld.isIcann) {
            throw new TranslatableError("domain_expiry_unsupported_is_icann", {
                // If domain is null, use hostname as fallback for better error message.
                domain: tld.domain ?? tld.hostname ?? "EMPTY DOMAIN",
                publicSuffix: tld.publicSuffix,
            });
        }
        if (!tld.domain) {
            throw new TranslatableError("domain_expiry_unsupported_missing_target");
        }

        const publicSuffix = tld.publicSuffix;
        const rootTld = publicSuffix.split(".").pop();
        if (!(await getDomainExpiryLookup(rootTld))) {
            throw new TranslatableError("domain_expiry_unsupported_unsupported_tld_no_rdap_endpoint", {
                publicSuffix,
            });
        }

        return {
            domain: tld.domain,
            tld: rootTld,
        };
    }

    /**
     * @param {string} domainName Domain name
     * @returns {Promise<DomainExpiry>} Domain expiry bean
     */
    static async findByDomainNameOrCreate(domainName) {
        let domain = await DomainExpiry.findByName(domainName);
        if (!domain && domainName) {
            domain = await DomainExpiry.createByName(domainName);
        }
        return domain;
    }

    /**
     * @returns {number} number of days remaining before expiry
     */
    get daysRemaining() {
        // redbean stores expiry as a local SQL datetime.
        return dayjs(this.expiry).utc().diff(dayjs.utc(), "day");
    }

    /**
     * @returns {Promise<(Date|null)>} Expiry date from the registry
     */
    async getExpiryDate() {
        const domain = domainToASCII(this.domain);
        const lookup = await getDomainExpiryLookup(domain.split(".").pop());
        return lookup ? lookup(domain) : null;
    }

    /**
     * @param {string} domainName Monitor object
     * @throws {TranslatableError} If the domain is not supported
     * @returns {Promise<Date | undefined>} the expiry date
     */
    static async checkExpiry(domainName) {
        let bean = await DomainExpiry.findByDomainNameOrCreate(domainName);
        let expiryDate;

        if (bean?.lastCheck && dayjs.utc().diff(dayjs.utc(bean.lastCheck), "day") < 1) {
            log.debug("domain_expiry", `Domain expiry already checked recently for ${bean.domain}, won't re-check.`);
            return bean.expiry;
        } else if (bean) {
            expiryDate = await bean.getExpiryDate();

            if (dayjs.utc(expiryDate).isAfter(dayjs(bean.expiry))) {
                bean.lastExpiryNotificationSent = null;
            }

            bean.domain = domainToASCII(bean.domain);
            bean.expiry = expiryDate === null ? null : R.isoDateTimeMillis(expiryDate);
            bean.lastCheck = R.isoDateTimeMillis(dayjs.utc());
            await R.store(bean);
        }

        if (expiryDate === null) {
            return;
        }

        return expiryDate;
    }

    /**
     * @param {string} domainName the domain name to send notifications for
     * @param {LooseObject<any>[]} notificationList notification List
     * @returns {Promise<void>}
     */
    static async sendNotifications(domainName, notificationList) {
        const domain = await DomainExpiry.findByDomainNameOrCreate(domainName);
        if (!notificationList.length > 0) {
            // fail fast. If no notification is set, all the following checks can be skipped.
            log.debug("domain_expiry", "No notification, no need to send domain notification");
            return;
        }
        // sanity check if expiry date is valid before calculating days remaining. Should not happen and likely indicates a bug in the code.
        if (!domain.expiry || isNaN(new Date(domain.expiry).getTime())) {
            log.warn(
                "domain_expiry",
                `No valid expiry date passed to sendNotifications for ${domainName} (expiry: ${domain.expiry}), skipping notification`
            );
            return;
        }

        const daysRemaining = domain.daysRemaining;
        const lastSent = domain.lastExpiryNotificationSent;
        log.debug("domain_expiry", `${domainName} expires in ${daysRemaining} days`);

        let notifyDays = await setting("domainExpiryNotifyDays");
        if (notifyDays == null || !Array.isArray(notifyDays)) {
            // Reset Default
            await setSetting("domainExpiryNotifyDays", [7, 14, 21], "general");
            notifyDays = [7, 14, 21];
        }
        if (Array.isArray(notifyDays)) {
            // Asc sort to avoid sending multiple notifications if daysRemaining is below multiple targetDays
            notifyDays.sort((a, b) => a - b);
            for (const targetDays of notifyDays) {
                if (daysRemaining > targetDays) {
                    log.debug(
                        "domain_expiry",
                        `No need to send domain notification for ${domainName} (${daysRemaining} days valid) on ${targetDays} deadline.`
                    );
                    continue;
                } else if (lastSent && lastSent <= targetDays) {
                    log.debug(
                        "domain_expiry",
                        `Notification for ${domainName} on ${targetDays} deadline sent already, no need to send again.`
                    );
                    continue;
                }
                const sent = await sendDomainNotificationByTargetDays(
                    domainName,
                    daysRemaining,
                    targetDays,
                    notificationList
                );
                if (sent) {
                    domain.lastExpiryNotificationSent = targetDays;
                    await R.store(domain);
                    return targetDays;
                }
            }
        }
    }
}

module.exports = DomainExpiry;
