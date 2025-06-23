/*
Quantumult X Resource Parser for YAML Proxies (Updated Version)

Usage:
1. Save this code as a .js file (e.g., `hm_parser.js`).
2. Host the `hm.yaml` file and this `hm_parser.js` file on a server or a gist.
3. In Quantumult X, add a resource parser entry:
   [General]
   resource_parser_url = "http://your-server.com/hm_parser.js" // Or your gist raw link
   resource_parser_parameter = "http://your-server.com/hm.yaml" // Or your hm.yaml raw link

   [Rewrite_Remote] or [Filter_Remote] (Highly Recommended for updates)
   http://your-server.com/hm.yaml, tag=YourProxies, update-interval=86400, opt-parser=true, enabled=true

*/

/**
 * A simplified YAML parser for the specific structure of the provided hm.yaml.
 * This function extracts top-level keys, and specifically handles 'proxies' and 'rules'.
 * @param {string} yamlString The full YAML content as a string.
 * @returns {object} An object containing parsed data (proxies, rules, etc.).
 */
function parseYaml(yamlString) {
    const lines = yamlString.split('\n');
    const result = {
        proxies: [],
        rules: [],
        'proxy-groups': [] // Initialize even if not in the provided snippet
    };
    let inProxiesSection = false;
    let inProxyGroupsSection = false;

    for (const line of lines) {
        const trimmedLine = line.trim();
        if (!trimmedLine || trimmedLine.startsWith('#')) {
            continue; // Skip empty lines and comments
        }

        // Detect section headers
        if (trimmedLine.startsWith('proxies:')) {
            inProxiesSection = true;
            inProxyGroupsSection = false;
            continue;
        } else if (trimmedLine.startsWith('proxy-groups:')) {
            inProxiesSection = false;
            inProxyGroupsSection = true;
            continue;
        } else if (trimmedLine.includes(':') && !trimmedLine.startsWith('- ')) {
            // Top-level key that is not a list item, potentially ends a section
            inProxiesSection = false;
            inProxyGroupsSection = false;
            // You could parse other top-level keys here if needed
            continue;
        }

        // Parse proxies
        if (inProxiesSection && trimmedLine.startsWith('- {')) {
            try {
                // Extract content within {}
                const proxyString = trimmedLine.substring(trimmedLine.indexOf('{') + 1, trimmedLine.lastIndexOf('}'));
                const proxy = {};
                // Split by comma outside of nested objects/arrays (simplified for this specific YAML)
                proxyString.split(/,\s*(?![^{]*\})/).forEach(part => {
                    const [key, value] = part.split(':', 2).map(s => s.trim());
                    if (key && value) {
                        const cleanedValue = value.replace(/^"|"$/g, ''); // Remove surrounding quotes
                        if (cleanedValue === 'true') {
                            proxy[key] = true;
                        } else if (cleanedValue === 'false') {
                            proxy[key] = false;
                        } else if (!isNaN(cleanedValue) && cleanedValue.trim() !== '') {
                            proxy[key] = Number(cleanedValue);
                        } else if (key === 'ws-opts') {
                            // Special handling for ws-opts, assuming it's a simple key-value string inside {}
                            const wsOptsMatch = value.match(/^{([^}]+)}$/);
                            if (wsOptsMatch && wsOptsMatch[1]) {
                                proxy['ws-opts'] = {};
                                wsOptsMatch[1].split(',').forEach(wsPart => {
                                    const [wsKey, wsValue] = wsPart.split(':', 2).map(s => s.trim());
                                    if (wsKey && wsValue) {
                                        proxy['ws-opts'][wsKey] = wsValue.replace(/^"|"$/g, '');
                                    }
                                });
                            }
                        } else {
                            proxy[key] = cleanedValue;
                        }
                    }
                });
                result.proxies.push(proxy);
            } catch (e) {
                console.error("Error parsing proxy line:", line, e);
            }
        }
        // Parse proxy groups (if they were present, this part needs expansion based on exact format)
        else if (inProxyGroupsSection && trimmedLine.startsWith('- name:')) {
            // This part is a placeholder as no proxy groups were in the snippet
            // If you have proxy groups in your full YAML, this section needs to be developed
            console.warn("Proxy group parsing not fully implemented as no example provided.");
        }
        // Parse rules (assuming rules are top-level list items and not under a 'rules:' section)
        else if (!inProxiesSection && !inProxyGroupsSection && trimmedLine.startsWith('- IP-CIDR,')) {
            // For example: - IP-CIDR,103.72.12.0/22,🎯 全球直连,no-resolve
            result.rules.push(trimmedLine.substring(2).trim()); // Remove the '- ' prefix
        }
    }
    return result;
}

// Main function for Quantumult X
async function parse() {
    const url = $resource.parameter;
    if (!url) {
        $done({}); // Return empty if no URL parameter provided
        return;
    }

    try {
        const response = await $task.fetch({ url: url, method: 'GET' });
        const yamlContent = response.body;

        if (!yamlContent) {
            console.error("Fetched YAML content is empty.");
            $done({});
            return;
        }

        const parsedData = parseYaml(yamlContent);

        const qxConfig = {};
        const qxProxies = [];
        const qxProxyGroups = [];
        const qxRules = [];

        // Convert proxies to Quantumult X format
        if (parsedData.proxies && parsedData.proxies.length > 0) {
            parsedData.proxies.forEach(p => {
                const qxStringParts = [`${p.type}=${p.server}:${p.port}`];

                if (p.uuid) qxStringParts.push(`uuid=${p.uuid}`);
                if (p.password) qxStringParts.push(`password=${p.password}`); // For shadowsocks/trojan
                if (p.method) qxStringParts.push(`method=${p.method}`); // For shadowsocks
                if (p.cipher) qxStringParts.push(`method=${p.cipher}`); // Alias for shadowsocks method

                // Vmess specific
                if (p.alterId !== undefined) qxStringParts.push(`alter-id=${p.alterId}`);
                if (p.network === 'ws') qxStringParts.push(`obfs=ws`); // Obfuscation type
                if (p['ws-opts'] && p['ws-opts'].path) qxStringParts.push(`obfs-path=${p['ws-opts'].path}`);
                if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) {
                    qxStringParts.push(`obfs-header=Host:${p['ws-opts'].headers.Host}`);
                }

                // TLS specific
                if (p.tls !== undefined) qxStringParts.push(`tls=${p.tls ? 'true' : 'false'}`);
                if (p['skip-cert-verify'] !== undefined) qxStringParts.push(`skip-cert-verify=${p['skip-cert-verify'] ? 'true' : 'false'}`);
                if (p.servername) qxStringParts.push(`server-name=${p.servername}`);

                // Other general
                if (p.udp !== undefined) qxStringParts.push(`udp-relay=${p.udp ? 'true' : 'false'}`);
                if (p.tag) qxStringParts.push(`tag=${p.tag}`); // Use 'name' from YAML as 'tag' in QX

                qxProxies.push(qxStringParts.join(', '));
            });
            qxConfig.proxies = qxProxies;
        }

        // Convert proxy-groups to Quantumult X format (if present and parsed)
        if (parsedData['proxy-groups'] && parsedData['proxy-groups'].length > 0) {
             parsedData['proxy-groups'].forEach(group => {
                const groupParts = [`${group.type}=${group.name}`];
                if (group.proxies && group.proxies.length > 0) {
                    // This assumes group.proxies are just names from the main proxies list
                    groupParts.push(`${group.proxies.join(', ')}`);
                }
                qxProxyGroups.push(groupParts.join(', '));
            });
            qxConfig.proxy_groups = qxProxyGroups;
        }


        // Convert rules to Quantumult X format
        if (parsedData.rules && parsedData.rules.length > 0) {
            parsedData.rules.forEach(rule => {
                // Quantumult X rule format: TYPE,VALUE,POLICY,OPTIONS
                // Example YAML: IP-CIDR,103.72.12.0/22,🎯 全球直连,no-resolve
                // Quantumult X: IP-CIDR,103.72.12.0/22,🎯 全球直连
                const parts = rule.split(',');
                if (parts.length >= 3) {
                    // Remove 'no-resolve' if it's the last part, as it's often optional or implied in QX
                    const qxRule = parts.slice(0, 3).join(','); // Take Type, Value, Policy
                    qxRules.push(qxRule.trim());
                } else {
                    console.warn("Skipping malformed rule:", rule);
                }
            });
            qxConfig.rules = qxRules;
        }

        $done(qxConfig);

    } catch (error) {
        console.error("Error fetching or parsing resource:", error);
        $done({}); // Ensure something is returned even on error to prevent indefinite loading
    }
}

parse();
