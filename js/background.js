const whoisUrl = 'https://www.whoisxmlapi.com/whoisserver/WhoisService';
const geoIpUrl = "https://ip-geolocation.whoisxmlapi.com/api/v1";
const gsbUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const mcAfeeUrl = 'https://www.siteadvisor.com/sitereport.html';
const nortonUrl = 'https://safeweb.norton.com/report/show';
const phishTankUrl = 'http://checkurl.phishtank.com/checkurl/';
const scamadviserUrl = 'https://www.scamadviser.com/check-website/';
const bitdefenderUrl = 'http://trafficlight.bitdefender.com/info';
let tabs = {};

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    updateTabs(tab);
});

chrome.tabs.onRemoved.addListener(function (tabId, removeInfo) {
    delete tabs[tabId];
});

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.sender === 'popup') {
        switch (message.type) {
            case 'opened':
                chrome.tabs.query({ active: true }, function (tabs) {
                    render(updateTabs(tabs[0]));
                });
                sendResponse(true);
                break;
            case 'scan':
                sendResponse(true);
                chrome.tabs.query({ active: true }, function (tabs) {
                    scan(tabs[0].id);
                });
                break;
        }
    }
});

function updateTabs(tab) {
    if (!tabs[tab.id] || tabs[tab.id].url !== getDomainFromUrl(tab.url)) {
        tabs[tab.id] = {
            url: getDomainFromUrl(tab.url),
            tabId: tab.id,
            scanStarted: false,
            passed: {
                safe: 0,
                danger: 0,
                warning: 0,
                unknown: 0
            },
            status: 'loading',
            whois: null,
            geoIp: null,
            gsb: {
                status: 'loading'
            },
            mcAfee: {
                status: 'loading'
            },
            norton: {
                status: 'loading'
            },
            phishTank: {
                status: 'loading'
            },
            scamAdviser: {
                status: 'loading'
            },
            bitdefender: {
                status: 'loading'
            }
        };
    }
    console.log(tabs);
    return tabs[tab.id];
}

function getDomainFromUrl(url) {
    return url.startsWith('http') ? (new URL(url)).hostname : '';
}

function getUrl(url, params) {
    let _url = new URL(url);
    Object.keys(params).forEach(key => _url.searchParams.append(key, params[key]));
    return _url.toString();
}

async function whois(domain) {
    try {
        const params = {
            apiKey: 'at_9GrOTFl2jiW8khWJbAsjqRuwAKtEw',
            domainName: domain,
            outputFormat: 'json'
        };
        const resp = await fetch(getUrl(whoisUrl, params));
        const data = await resp.json();
        return {
            createdDate: data.WhoisRecord.createdDate,
            expiresDate: data.WhoisRecord.expiresDate,
            registrant: data.WhoisRecord.registrant ? {
                organization: data.WhoisRecord.registrant.organization || '',
                country: data.WhoisRecord.registrant.country || '',
                address: data.WhoisRecord.registrant.city + ', ' + data.WhoisRecord.registrant.street1 || '',
                telephone: data.WhoisRecord.registrant.telephone || ''
            } : {organization: '', country: '', address: '', telephone: ''}
        };
    } catch (e) {
        console.log('Whois failed: ', e);
    }
}

async function geoIP(domain) {
    try {
        const params = {
            apiKey: 'at_9GrOTFl2jiW8khWJbAsjqRuwAKtEw',
            domainName: domain,
        };
        const resp = await fetch(getUrl(geoIpUrl, params));
        const data = await resp.json();
        return {
            ip: data.ip,
            address: data.location.city + ', ' + data.location.region + ', ' + data.location.country
        }
    } catch (e) {
        console.log('GeoIP failed: ', e);
    }
}

async function gsb(domain) {
    try {
        const key = 'AIzaSyDyUjlKUwQrwPIO6TL2OARrBrhDqYuzeyk';
        const reqGSB = {
            "client": {
                "clientId": "urlscanner",
                "clientVersion": "0.0.9"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING",
                    "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM", "PLATFORM_TYPE_UNSPECIFIED"],
                "threatEntryTypes": ["URL", "EXECUTABLE", "THREAT_ENTRY_TYPE_UNSPECIFIED"],
                "threatEntries": [
                    {"url": domain}
                ]
            }
        };

        const resp = await fetch(getUrl(gsbUrl, {key}), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(reqGSB)
        });

        const data = await resp.json();
        return {
            status: Object.keys(data).length === 0 ? 'safe' : 'danger'
        };
    } catch (e) {
        console.log('Google Safebrowsing failed: ', e);
    }
}

async function mcAfee(domain) {
    try {
        const resp = await fetch(getUrl(mcAfeeUrl, {url: domain}));
        const data = await resp.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(data, 'text/html');
        const classes = doc.getElementsByClassName('container')[0].classList;
        if (classes.contains('safe')) {
            return {status: 'safe'}
        } else if (classes.contains('danger')) {
            return {status: 'danger'}
        } else if (classes.contains('warning')) {
            return {status: 'warning'}
        } else {
            return {status: 'unknown'}
        }
    } catch (e) {
        console.log('McAfee failed: ', e);
        return {status: 'unknown'};
    }
}

async function norton(domain) {
    try {
        const resp = await fetch(getUrl(nortonUrl, {url: domain}));
        const data = await resp.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(data, 'text/html');
        const status = doc.querySelector('div.big_rating_wrapper ~ b').innerText;
        switch (status) {
            case 'SAFE':
                return {status: 'safe'};
            case 'WARNING':
                return {status: 'danger'};
            case 'CAUTION':
                return {status: 'warning'};
            case 'UNTESTED':
                return {status: 'unknown'};
        }
    } catch (e) {
        console.log('Norton failed: ', e);
        return {status: 'unknown'};
    }
}

async function phishTank(domain) {
    try {
        const resp = await fetch(phishTankUrl, {
            method: 'POST',
            headers: {
                'User-Agent': 'phishtank/besnosyuk',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${domain}&format=json&
            app_key=08fc7064832ecf5f4b8dc7f6534ea4e97acc3900dad26e9549f3870c29591ae2`
        });
        const data = await resp.json();
        if (data.results.in_database && data.results.verified) {
            return {status: data.results.valid ? 'danger' : 'safe',
                externalUrl: data.results.phish_detail_page};
        } else {
            return {status: 'unknown'};
        }
    } catch (e) {
        console.log('PhishTank failed: ', e);
        return {status: 'unknown'};
    }
}

async function scamadviser(domain) {
    try {
        const resp = await fetch(scamadviserUrl + domain);
        const data = await resp.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(data, 'text/html');
        const rate = parseInt(doc.getElementsByClassName(
            'global_trust__overlay-square')[0].innerText);
        return {status: rate > 70 ? 'safe' : rate > 40 ? 'warning' : 'danger'};
    } catch (e) {
        console.log('scamadviser failed: ', e);
        return {status: 'unknown'};
    }
}

async function bitdefender(domain) {
    try {
        const resp = await fetch(getUrl(bitdefenderUrl, { url: domain }));
        const data = await resp.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(data, 'text/html');
        if (doc.querySelector('.container-displayed .infected-text')) {
            return {status: 'danger'};
        } else if (doc.querySelector('.container-displayed .unsafe-text')) {
            return {status: 'warning'};
        } else if (doc.querySelector('.container-displayed .grey-text') ||
            doc.querySelector('.container-displayed .green-text')) {
            return {status: 'safe'};
        } else {
            return {status: 'unknown'};
        }
    } catch (e) {
        console.log('Bitdefender failed: ', e);
        return {status: 'unknown'};
    }
}

function scan(tabId) {
    const tab = tabs[tabId];
    tab.scanStarted = true;
    render(tab);

    whois(tab.url).then(resp => {
        tab.whois = resp;
        render(tab);
    });

    geoIP(tab.url).then(resp => {
        tab.geoIp = resp;
        render(tab);
    });

    gsb(tab.url).then(resp => {
        tab.gsb = resp;
        tab.passed[tab.gsb.status]++;
        render(tab);
    });

    mcAfee(tab.url).then(resp => {
        tab.mcAfee = resp;
        tab.passed[tab.mcAfee.status]++;
        render(tab);
    });

    norton(tab.url).then(resp => {
        tab.norton = resp;
        tab.passed[tab.norton.status]++;
        render(tab);
    });

    Promise.all([
        phishTank('http://' + tab.url),
        phishTank('https://' + tab.url),
        phishTank('http://' + tab.url + '/'),
        phishTank('https://' + tab.url + '/')
    ]).then(resp => {
        tab.phishTank =
            resp.find(s => s.status === 'danger') ||
            resp.find(s => s.status === 'safe') ||
            {status: 'unknown'};
        tab.passed[tab.phishTank.status]++;
        render(tab);
    });

    scamadviser(tab.url).then(resp => {
        tab.scamAdviser = resp;
        tab.passed[tab.scamAdviser.status]++;
        render(tab);
    });

    bitdefender(tab.url).then(resp => {
        tab.bitdefender = resp;
        tab.passed[tab.bitdefender.status]++;
        render(tab);
    });
}

function render(tab) {
    if (tabs[tab.tabId] && tabs[tab.tabId].url === tab.url) {
        tabs[tab.tabId] = tab;
    }
    chrome.runtime.sendMessage(
        { sender: 'background', type: 'render', data: tabs[tab.tabId] },
        function(response) {});
}
