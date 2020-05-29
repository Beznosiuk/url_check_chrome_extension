document.addEventListener('DOMContentLoaded', function () {
    chrome.runtime.sendMessage({ sender: 'popup', type: 'opened' }, function(response) {});
});

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    console.log('Popup on message: ', message);
    if (message.sender === 'background') {
        if (message.type === 'render') {
            render(message.data);
        }
    }
    sendResponse(true);
});

function render(data) {
    const app = document.getElementById('app');
    const showResult = Object.values(data.passed).reduce((a, c) => a + c, 0) === 6;

    if (showResult) {
        if (data.passed.danger > 0) {
            data.status = 'danger';
        } else if (data.passed.warning > 0) {
            data.status = 'warning';
        } else if (data.passed.safe > 0) {
            data.status = 'safe';
        } else {
            data.status = 'unknown';
        }
    }

    app.innerHTML = `
    <div class="top-block ${ data.status }">
        ${data.scanStarted ? `
        <div class="result">
            <div class="result-icon-container">
                <img src="../images/icons/${ data.status }.svg" alt="">
            </div>
            <div class="result-stat">
                <div class="result-stat__item">
                    Безпечно: <span>${data.passed.safe}</span>
                </div>
                <div class="result-stat__item">
                    Небезпечно: <span>${data.passed.danger}</span>
                </div>
                <div class="result-stat__item">
                    Можливо небезпечно: <span>${data.passed.warning}</span>
                </div>
                <div class="result-stat__item">
                    Невідомо: <span>${data.passed.unknown}</span>
                </div>
            </div>
        </div>` : ''}
        <div class="url-container">
            <div class="url">${data.url ? data.url : 'Цю сторінку не можна сканувати'}</div>
            ${(data.scanStarted || !data.url) ? '' : '<button class="button" id="scan-button">Перевірити</button>'}
            <div class="base-info-container">
                ${data.whois ? `
                    <div class="base-info-section">
                    <div class="base-info__section__heading">Домен</div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Дата створення:</div>
                        <div class="base-info-item__value">${data.whois.createdDate}</div>
                    </div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Дата закінчення дії:</div>
                        <div class="base-info-item__value">${data.whois.expiresDate}</div>
                    </div>
                </div>

                <div class="base-info-section">
                    <div class="base-info__section__heading">Реєстрант</div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Організація:</div>
                        <div class="base-info-item__value">${data.whois.registrant.organization}</div>
                    </div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Країна:</div>
                        <div class="base-info-item__value">${data.whois.registrant.country}</div>
                    </div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Адреса:</div>
                        <div class="base-info-item__value">${data.whois.registrant.address}</div>
                    </div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Телефон:</div>
                        <div class="base-info-item__value">${data.whois.registrant.telephone}</div>
                    </div>
                </div>
                ` : ''}
                
                ${data.geoIp ? `
                <div class="base-info-section">
                    <div class="base-info__section__heading">Сервер</div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">IP адреса:</div>
                        <div class="base-info-item__value">${data.geoIp.ip}</div>
                    </div>
                    <div class="base-info-item">
                        <div class="base-info-item__title">Місцезнаходження:</div>
                        <div class="base-info-item__value">${data.geoIp.address}</div>
                    </div>
                </div>` : ''}
            </div>
        </div>
    </div>
    ${data.scanStarted ? `
    <div class="checks-container">
        <div class="flex-row">
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.gsb.status}.svg" alt="">
                <div class="title">
                    Google Safe Browsing
                </div>
                <a href="https://transparencyreport.google.com/safe-browsing/search?url=${data.url}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>
            </div>
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.mcAfee.status}.svg" alt="">
                <div class="title">
                    McAfee
                </div>
                <a href="https://www.siteadvisor.com/sitereport.html?url=${data.url}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>
            </div>
        </div>
        <div class="flex-row">
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.norton.status}.svg" alt="">
                <div class="title">
                    Norton
                </div>
                <a href="https://safeweb.norton.com/report/show?url=${data.url}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>
            </div>
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.phishTank.status}.svg" alt="">
                <div class="title">
                    PhishTank
                </div>
                ${data.phishTank.externalUrl ? `
                <a href="${data.phishTank.externalUrl}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>` : ''}
            </div>
        </div>
        <div class="flex-row">
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.scamAdviser.status}.svg" alt="">
                <div class="title">
                    Scam Adviser
                </div>
                <a href="https://www.scamadviser.com/check-website/${data.url}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>
            </div>
            <div class="check-item">
                <img class="result-icon" src="../images/icons/${data.bitdefender.status}.svg" alt="">
                <div class="title">
                    Bitdefender
                </div>
                <a href="http://trafficlight.bitdefender.com/info?url=${data.url}" 
                    target="_blank"
                    class="external-link">
                    <img src="../images/icons/external.svg" alt="">
                </a>
            </div>
        </div>
    </div>` : ''}
    `;

    const button = document.getElementById('scan-button');
    if (button && !data.scanStarted) {
        button.addEventListener('click', function () {
            chrome.runtime.sendMessage({ sender: 'popup', type: 'scan' }, function(response) {})
        });
    }
}
