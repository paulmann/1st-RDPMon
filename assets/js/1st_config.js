/*
 * IP WHOIS Lookup Tool v3.0
 * Author: Mikhail Deynekin, [mid1977@gmail.com](mailto:mid1977@gmail.com)
 * Website: [https://deynekin.com](https://deynekin.com)
 */

window.APP_STATE = window.APP_STATE || { settings: {} };

const ipServicesMap = [
    { value: 'afrinic', label: 'AFRINIC (Africa)', url: 'https://whois.afrinic.net/whois?form_type=simple&searchtext={IP}' },
    { value: 'apnic', label: 'APNIC (Asia-Pacific)', url: 'https://wq.apnic.net/whois-search/static/search.html?searchtext={IP}' },
    { value: 'arin', label: 'ARIN (North America)', url: 'https://search.arin.net/rdap/?query={IP}' },
    { value: 'bigdatacloud', label: 'BigDataCloud', url: 'https://www.bigdatacloud.com/ip-lookup/{IP}' },
    { value: 'dbip', label: 'DB-IP', url: 'https://db-ip.com/{IP}' },
    { value: 'dnschecker', label: 'DNSChecker.org', url: 'https://dnschecker.org/ip-whois-lookup.php?query={IP}' },
    { value: 'hackertarget', label: 'HackerTarget', url: 'https://hackertarget.com/whois-lookup/?q={IP}' },
    { value: 'iphey', label: 'IPhey.com', url: 'https://iphey.com/ip/{IP}' },
    { value: 'iphub', label: 'IPHub.info', url: 'https://iphub.info/?ip={IP}' },
    { value: 'ipinfo', label: 'IPinfo.io', url: 'https://ipinfo.io/{IP}' },
    { value: 'iplocation', label: 'IPLocation.io', url: 'https://iplocation.io/ip-location/{IP}' },
    { value: 'ip2location', label: 'IP2Location', url: 'https://www.ip2location.com/demo/{IP}' },
    { value: 'lacnic', label: 'LACNIC (Latin America)', url: 'https://rdap.lacnic.net/rdap/ip/{IP}' },
    { value: 'netlas', label: 'Netlas.io', url: 'https://netlas.io/search?q={IP}' },
    { value: 'ripe', label: 'RIPE NCC (Europe)', url: 'https://stat.ripe.net/resource/{IP}', default: true },
    { value: 'whatismyip', label: 'WhatIsMyIP.com', url: 'https://www.whatismyip.com/ip-whois-lookup/?query={IP}' },
    { value: 'whoiscom', label: 'Whois.com', url: 'https://www.whois.com/whois/{IP}' },
    { value: 'whoisology', label: 'Whoisology.com', url: 'https://www.whoisology.com/whois/{IP}' },
    { value: 'who', label: 'Who.is', url: 'https://who.is/whois-ip/ip-address/{IP}' },
    { value: 'whois', label: 'Whois (DomainTools)', url: 'https://whois.domaintools.com/{IP}' }
];

const populateIpServiceSelect = (selectedValue = 'ripe') => {
    const select = document.getElementById('ip-info-service');
    if (!select) return;
    
    select.innerHTML = ipServicesMap.map(service => 
        `<option value="${service.value}" ${service.value === selectedValue ? 'selected' : ''}>
            ${service.label}
        </option>`
    ).join('');
    
    const savedValue = APP_STATE.settings.ipInfoService || 'ripe';
    select.value = savedValue;
};

document.addEventListener('DOMContentLoaded', () => {
    populateIpServiceSelect();
    
    document.getElementById('ip-info-service').addEventListener('change', (e) => {
        APP_STATE.settings.ipInfoService = e.target.value;
    });
});

const getIpServiceUrl = (service, ip) => {
    const cleanIp = ip.replace(/"/g, '').trim();
    const srv = ipServicesMap.find(s => s.value === service) || ipServicesMap.find(s => s.default);
    return srv.url.replace('{IP}', cleanIp);
};