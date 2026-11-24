process.env.UPTIME_KUMA_HIDE_LOG = ["info_db", "info_server"].join(",");

const { describe, test, mock, before, after } = require("node:test");
const assert = require("node:assert");
const net = require("node:net");
const { Duplex } = require("node:stream");
const DomainExpiry = require("../../server/model/domain_expiry");
const mockWebhook = require("./notification-providers/mock-webhook");
const TestDB = require("../mock-testdb");
const { R } = require("redbean-node");
const { Notification } = require("../../server/notification");
const { setSetting } = require("../../server/util");
const dayjs = require("dayjs");
const { retryExternalService } = require("./test-util");

const testDb = new TestDB("./data/test-domain");
const rdapBootstrap = {
    services: require("../../extra/rdap-dns.json").services.map(([tlds, urls]) => [
        tlds.filter((tld) => !["ru", "xn--p1ai", "su"].includes(tld)),
        urls,
    ]),
};

describe("Domain Expiry", () => {
    const monHttpCom = {
        type: "http",
        url: "https://www.google.com",
        domainExpiryNotification: true,
    };

    before(async () => {
        await testDb.create();
        Notification.init();
        // Pin registry discovery so these tests also work if IANA adds a TCI endpoint.
        const bootstrapFetch = mock.method(globalThis, "fetch", async () => ({ ok: true, json: () => rdapBootstrap }));
        try {
            await DomainExpiry.checkSupport(monHttpCom);
        } finally {
            bootstrapFetch.mock.restore();
        }
    });

    after(async () => {
        await testDb.destroy();
    });

    describe("TCI domain expiry", () => {
        // Relevant fields from the public TCI registry responses, in wire order.
        const records = [
            ["tcinet.ru", "tcinet.ru", "2027-07-06T21:00:00Z", "2027-08-07"],
            ["кц.рф", "xn--j1ay.xn--p1ai", "2027-11-25T08:15:46Z", "2027-12-26"],
            ["site.su", "site.su", "2027-06-26T21:00:00Z", "2027-07-30"],
        ];

        /**
         * Capture the wire query and supply a registry reply through a socket-like stream.
         * @param {import("node:test").TestContext} t Test context
         * @param {string|null} response Raw WHOIS reply, or null to leave the stream open
         * @returns {string[]} Queries written to the stream
         */
        function mockWhois(t, response) {
            const queries = [];
            t.mock.method(net, "createConnection", ({ host, port, signal }) => {
                assert.strictEqual(host, "whois.tcinet.ru");
                assert.strictEqual(port, 43);
                return new Duplex({
                    signal,
                    read() {},
                    write(chunk, encoding, done) {
                        queries.push(chunk.toString());
                        if (response !== null) {
                            this.push(response);
                            this.push(null);
                        }
                        done();
                    },
                });
            });
            return queries;
        }

        for (const [name, ascii, paidTill, freeDate] of records) {
            test(`uses the registry deadline for ${name} and caches by ASCII domain`, async (t) => {
                const reply = `% TCI\r\n\r\ndomain:        ${ascii.toUpperCase()}\r\npaid-till:     ${paidTill}\r\nfree-date:     ${freeDate}\r\nsource:        TCI\r\n`;
                const queries = mockWhois(t, reply);
                const target = await DomainExpiry.checkSupport({ type: "http", url: `https://www.${name}/path` });
                const hostname = await DomainExpiry.checkSupport({ type: "port", hostname: ascii });
                assert.deepStrictEqual(target, { domain: ascii, tld: ascii.split(".").pop() });
                assert.deepStrictEqual(target, hostname);
                assert.deepStrictEqual(await DomainExpiry.checkExpiry(target.domain), new Date(paidTill));
                await DomainExpiry.checkExpiry(name);
                assert.deepStrictEqual(queries, [ascii + "\r\n"]);
                assert.strictEqual((await DomainExpiry.findByName(name)).domain, ascii);
            });
        }

        const domainLine = "domain: example.ru\r\n";
        for (const [description, reply] of [
            ["unknown domain", "% No entries found for the selected source(s)."],
            ["rate limit", "% You have exceeded allowed connection rate."],
            ["missing paid-till", domainLine + "free-date: 2027-02-03"],
            ["invalid calendar date", domainLine + "paid-till: 2027-02-30T00:00:00Z"],
            ["another record's date", domainLine + "\r\ndomain: other.ru\r\npaid-till: 2027-01-01T00:00:00Z"],
            ["ambiguous domain", domainLine + "domain: other.ru\r\npaid-till: 2027-01-01T00:00:00Z"],
            ["oversized response", domainLine + "paid-till: 2027-01-01T00:00:00Z\r\n" + "x".repeat(65536)],
        ]) {
            test(`ignores a WHOIS response with ${description}`, async (t) => {
                mockWhois(t, reply);
                assert.strictEqual(await DomainExpiry.createByName("example.ru").getExpiryDate(), null);
            });
        }

        test("a timed out lookup caches an empty expiry and sends no notification", async (t) => {
            const controller = new AbortController();
            t.mock.method(AbortSignal, "timeout", (ms) => {
                assert.strictEqual(ms, 5000);
                setImmediate(() => controller.abort());
                return controller.signal;
            });
            const queries = mockWhois(t, null);
            const send = t.mock.method(Notification, "send", () => {});
            assert.strictEqual(await DomainExpiry.checkExpiry("timeout.ru"), undefined);
            assert.strictEqual(await DomainExpiry.checkExpiry("timeout.ru"), null);
            await DomainExpiry.sendNotifications("timeout.ru", [{ config: "{}" }]);
            assert.deepStrictEqual(queries, ["timeout.ru\r\n"]);
            assert.strictEqual(send.mock.callCount(), 0);
        });

        test("prefers an IANA-listed RDAP endpoint even for a TCI domain", async (t) => {
            rdapBootstrap.services.unshift([["ru"], ["https://rdap.example/"]]);
            t.after(() => rdapBootstrap.services.shift());
            const queries = mockWhois(t, null);
            const expiry = "2028-01-01T00:00:00Z";
            const fetch = t.mock.method(globalThis, "fetch", async () => ({
                status: 200,
                json: () => ({ events: [{ eventAction: "expiration", eventDate: expiry }] }),
            }));
            const bean = DomainExpiry.createByName("example.ru");
            assert.deepStrictEqual(await bean.getExpiryDate(), new Date(expiry));
            assert.deepStrictEqual(fetch.mock.calls[0].arguments, ["https://rdap.example/domain/example.ru"]);
            assert.deepStrictEqual(queries, []);
        });

        test("rejects a bare registry suffix", async () => {
            await assert.rejects(DomainExpiry.checkSupport({ type: "http", url: "https://рф/" }), {
                message: "domain_expiry_unsupported_missing_target",
            });
        });
    });

    test("reuses existing Unicode expiry records when looking up the ASCII name", async (t) => {
        const legacy = R.dispense("domain_expiry");
        legacy.domain = "bücher.com";
        const expiry = new Date("2028-05-06T19:00:00Z");
        legacy.expiry = R.isoDateTimeMillis(expiry);
        legacy.lastCheck = R.isoDateTimeMillis(dayjs.utc().subtract(2, "days"));
        legacy.lastExpiryNotificationSent = 1000;
        await R.store(legacy);
        t.mock.method(globalThis, "fetch", async () => ({
            status: 200,
            json: () => ({ events: [{ eventAction: "expiration", eventDate: expiry.toISOString() }] }),
        }));
        await DomainExpiry.checkExpiry("xn--bcher-kva.com");
        const updated = await DomainExpiry.findByName("bücher.com");
        assert.strictEqual(updated.id, legacy.id);
        assert.strictEqual(updated.domain, "xn--bcher-kva.com");
        assert.strictEqual(updated.lastExpiryNotificationSent, 1000);
        assert.strictEqual(updated.daysRemaining, dayjs.utc(expiry).diff(dayjs.utc(), "day"));
    });

    test("getExpiryDate() returns correct expiry date for .wiki domain with no A record", async () => {
        await retryExternalService(async () => {
            const d = DomainExpiry.createByName("google.wiki");
            assert.deepEqual(await d.getExpiryDate(), new Date("2026-11-26T23:59:59.000Z"));
        });
    });

    describe("checkSupport()", () => {
        test("allows and correctly parses http monitor with valid domain", async () => {
            const supportInfo = await DomainExpiry.checkSupport(monHttpCom);
            let expected = {
                domain: "google.com",
                tld: "com",
            };
            assert.deepStrictEqual(supportInfo, expected);
        });

        describe("Target Validation", () => {
            test("throws error for empty string target", async () => {
                const monitor = {
                    type: "http",
                    url: "",
                    domainExpiryNotification: true,
                };
                await assert.rejects(
                    async () => await DomainExpiry.checkSupport(monitor),
                    (error) => {
                        assert.strictEqual(error.constructor.name, "TranslatableError");
                        assert.strictEqual(error.message, "domain_expiry_unsupported_missing_target");
                        return true;
                    }
                );
            });

            test("throws error for undefined target", async () => {
                const monitor = {
                    type: "http",
                    domainExpiryNotification: true,
                };
                await assert.rejects(
                    async () => await DomainExpiry.checkSupport(monitor),
                    (error) => {
                        assert.strictEqual(error.constructor.name, "TranslatableError");
                        assert.strictEqual(error.message, "domain_expiry_unsupported_missing_target");
                        return true;
                    }
                );
            });

            test("throws error for null target", async () => {
                const monitor = {
                    type: "http",
                    url: null,
                    domainExpiryNotification: true,
                };
                await assert.rejects(
                    async () => await DomainExpiry.checkSupport(monitor),
                    (error) => {
                        assert.strictEqual(error.constructor.name, "TranslatableError");
                        assert.strictEqual(error.message, "domain_expiry_unsupported_missing_target");
                        return true;
                    }
                );
            });
        });

        describe("Domain Parsing", () => {
            test("throws error for non-ICANN TLD (e.g. .local)", async () => {
                const monitor = {
                    type: "http",
                    url: "https://example.local",
                    domainExpiryNotification: true,
                };
                await assert.rejects(
                    async () => await DomainExpiry.checkSupport(monitor),
                    (error) => {
                        assert.strictEqual(error.constructor.name, "TranslatableError");
                        assert.strictEqual(error.message, "domain_expiry_unsupported_is_icann");
                        return true;
                    }
                );
            });
        });

        describe("Edge Cases & RDAP Support", () => {
            test("handles subdomain correctly", async () => {
                const monitor = {
                    type: "http",
                    url: "https://api.staging.example.com/v1/users",
                    domainExpiryNotification: true,
                };
                const supportInfo = await DomainExpiry.checkSupport(monitor);
                assert.strictEqual(supportInfo.domain, "example.com");
                assert.strictEqual(supportInfo.tld, "com");
            });

            test("supports multi-level public suffix via RDAP fallback (e.g. com.br)", async () => {
                await retryExternalService(async () => {
                    const monitor = {
                        type: "http",
                        url: "https://record.com.br",
                        domainExpiryNotification: true,
                    };
                    const supportInfo = await DomainExpiry.checkSupport(monitor);
                    assert.strictEqual(supportInfo.domain, "record.com.br");
                    assert.strictEqual(supportInfo.tld, "br");
                });
            });

            test("handles complex subdomain correctly", async () => {
                const monitor = {
                    type: "http",
                    url: "https://mail.subdomain.example.org",
                    domainExpiryNotification: true,
                };
                const supportInfo = await DomainExpiry.checkSupport(monitor);
                assert.strictEqual(supportInfo.domain, "example.org");
                assert.strictEqual(supportInfo.tld, "org");
            });

            test("handles URL with port correctly", async () => {
                const monitor = {
                    type: "http",
                    url: "https://example.com:8080/api",
                    domainExpiryNotification: true,
                };
                const supportInfo = await DomainExpiry.checkSupport(monitor);
                assert.strictEqual(supportInfo.domain, "example.com");
                assert.strictEqual(supportInfo.tld, "com");
            });

            test("handles URL with query parameters correctly", async () => {
                const monitor = {
                    type: "http",
                    url: "https://example.com/search?q=test&page=1",
                    domainExpiryNotification: true,
                };
                const supportInfo = await DomainExpiry.checkSupport(monitor);
                assert.strictEqual(supportInfo.domain, "example.com");
                assert.strictEqual(supportInfo.tld, "com");
            });
        });
    });

    test("findByDomainNameOrCreate() retrieves expiration date for .com domain from RDAP", async () => {
        await retryExternalService(async () => {
            const domain = await DomainExpiry.findByDomainNameOrCreate("google.com");
            const expiryFromRdap = await domain.getExpiryDate(); // from RDAP
            assert.deepEqual(expiryFromRdap, new Date("2028-09-14T04:00:00.000Z"));
        });
    });

    test("checkExpiry() caches expiration date in database", async () => {
        await retryExternalService(async () => {
            await DomainExpiry.checkExpiry("google.com"); // RDAP -> Cache
            const domain = await DomainExpiry.findByName("google.com");
            assert(dayjs.utc().diff(dayjs.utc(domain.lastCheck), "second") < 5);
        });
    });

    test("sendNotifications() triggers notification for expiring domain", async () => {
        await DomainExpiry.findByName("google.com");
        const hook = {
            port: 3010,
            url: "capture",
        };
        const manyDays = 3650;
        await setSetting("domainExpiryNotifyDays", [manyDays], "general");
        const notif = R.convertToBean("notification", {
            config: JSON.stringify({
                type: "webhook",
                httpMethod: "post",
                webhookContentType: "json",
                webhookURL: `http://127.0.0.1:${hook.port}/${hook.url}`,
            }),
            active: 1,
            user_id: 1,
            name: "Testhook",
        });
        const [, data] = await Promise.all([
            DomainExpiry.sendNotifications("google.com", [notif]),
            mockWebhook(hook.port, hook.url),
        ]);
        assert.match(data.msg, /will expire in/);
    });

    test("sendNotifications() handles domain with null expiry without sending NaN", async () => {
        // Regression test for bug: "Domain name will expire in NaN days"
        // Mock findByDomainNameOrCreate to return a bean with null expiry
        const mockDomain = {
            domain: "test-null.com",
            expiry: null,
            lastExpiryNotificationSent: null,
        };

        mock.method(DomainExpiry, "findByDomainNameOrCreate", async () => mockDomain);

        try {
            const hook = {
                port: 3012,
                url: "should-not-be-called-null",
            };

            const notif = {
                name: "TestNullExpiry",
                config: JSON.stringify({
                    type: "webhook",
                    httpMethod: "post",
                    webhookContentType: "json",
                    webhookURL: `http://127.0.0.1:${hook.port}/${hook.url}`,
                }),
            };

            // Race between sendNotifications and mockWebhook timeout
            // If webhook is called, we fail. If it times out, we pass.
            const result = await Promise.race([
                DomainExpiry.sendNotifications("test-null.com", [notif]),
                mockWebhook(hook.port, hook.url, 500)
                    .then(() => {
                        throw new Error("Webhook was called but should not have been for null expiry");
                    })
                    .catch((e) => {
                        if (e.reason === "Timeout") {
                            return "timeout"; // Expected - webhook was not called
                        }
                        throw e;
                    }),
            ]);

            assert.ok(result === undefined || result === "timeout", "Should not send notification for null expiry");
        } finally {
            mock.restoreAll();
        }
    });

    test("sendNotifications() handles domain with undefined expiry without sending NaN", async () => {
        try {
            // Mock findByDomainNameOrCreate to return a bean with undefined expiry (newly created bean scenario)
            const mockDomain = {
                domain: "test-undefined.com",
                expiry: undefined,
                lastExpiryNotificationSent: null,
            };

            mock.method(DomainExpiry, "findByDomainNameOrCreate", async () => mockDomain);

            const hook = {
                port: 3013,
                url: "should-not-be-called-undefined",
            };

            const notif = {
                name: "TestUndefinedExpiry",
                config: JSON.stringify({
                    type: "webhook",
                    httpMethod: "post",
                    webhookContentType: "json",
                    webhookURL: `http://127.0.0.1:${hook.port}/${hook.url}`,
                }),
            };

            // Race between sendNotifications and mockWebhook timeout
            // If webhook is called, we fail. If it times out, we pass.
            const result = await Promise.race([
                DomainExpiry.sendNotifications("test-undefined.com", [notif]),
                mockWebhook(hook.port, hook.url, 500)
                    .then(() => {
                        throw new Error("Webhook was called but should not have been for undefined expiry");
                    })
                    .catch((e) => {
                        if (e.reason === "Timeout") {
                            return "timeout"; // Expected - webhook was not called
                        }
                        throw e;
                    }),
            ]);

            assert.ok(
                result === undefined || result === "timeout",
                "Should not send notification for undefined expiry"
            );
        } finally {
            mock.restoreAll();
        }
    });
});
