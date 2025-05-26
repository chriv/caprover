import * as fs from 'fs';

const CONFIG_OVERRIDE_PATH = '/captain/data/config-override.json';

function overrideConfigFromFile(baseConfig: any): void {
    try {
        if (fs.existsSync(CONFIG_OVERRIDE_PATH)) {
            const raw = fs.readFileSync(CONFIG_OVERRIDE_PATH, 'utf8');
            const userConfig = JSON.parse(raw);

            if (userConfig.certbotImageName) {
                baseConfig.certbotImageName = userConfig.certbotImageName;
            }

            if (userConfig.rootSslConfig) {
                baseConfig.rootSslConfig = userConfig.rootSslConfig;
            }
        }
    } catch (err) {
        console.error('Error loading config-override.json:', err);
    }
}

const CaptainConstants = {
    configOverridePath: CONFIG_OVERRIDE_PATH,

    configs: {
        certbotImageName: 'certbot/certbot:latest',
        rootSslConfig: undefined as
            | {
                  challengeType: 'dns-01';
                  dnsProvider: 'cloudflare';
                  credentialsFilePath: string;
                  propagationSeconds?: number;
              }
            | undefined,
    },
};

overrideConfigFromFile(CaptainConstants.configs);

export = CaptainConstants;
