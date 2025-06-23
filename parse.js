/*
Quantumult X Resource Parser for YAML Proxies

Usage:
1. Save this code as a .js file (e.g., `hm_parser.js`).
2. Host the `hm.yaml` file and this `hm_parser.js` file on a server or a gist.
3. In Quantumult X, add a resource parser entry:
   [General]
   resource_parser_url = "http://your-server.com/hm_parser.js" // Or your gist raw link
   resource_parser_parameter = "http://your-server.com/hm.yaml" // Or your hm.yaml raw link

   [Rewrite_Remote] (Optional, if you want to include the rules from the YAML)
   http://your-server.com/hm.yaml, tag=YourProxies, update-interval=86400, opt-parser=true, enabled=true

   [Filter_Remote] (Optional, if you want to include the rules from the YAML)
   http://your-server.com/hm.yaml, tag=YourProxies, update-interval=86400, opt-parser=true, enabled=true

*/

function parseYaml(yamlString) {
    const lines = yamlString.split('\n');
    const result = {};
    let currentKey = '';
    let inProxies = false;
    let inProxyGroup = false;

    for (const line of lines) {
        const trimmedLine = line.trim();
        if (!trimmedLine || trimmedLine.startsWith('#')) {
            continue;
        }

        if (trimmedLine.startsWith('proxies:')) {
            inProxies = true;
            result.proxies = [];
            continue;
        } else if (trimmedLine.startsWith('proxy-groups:')) {
            inProxyGroup = true;
            result['proxy-groups'] = [];
            inProxies = false; // Exit proxies section
            continue;
        } else if (trimmedLine.includes(':') && !trimmedLine.startsWith('- ')) { // Check for top-level keys
            const parts = trimmedLine.split(':', 2);
            currentKey = parts[0].trim();
            if (parts[1]) {
                result[currentKey] = parts[1].trim();
            }
            inProxies = false;
            inProxyGroup = false;
            continue;
        }

        if (inProxies && trimmedLine.startsWith('- {')) {
            // This is a proxy definition
            try {
                // Remove the starting '-' and parse as JSON, replacing single quotes with double quotes
                const jsonString = trimmedLine.substring(2).replace(/'/g, '"');
                // A more robust way to handle the YAML-like single-line object
                const cleanedJsonString = jsonString.replace(/(\w+): /g, '"$1": ').replace(/, (\w+):/g, ', "$1":');
                const proxy = JSON.parse(cleanedJsonString);

                // Map YAML keys to Quantumult X keys
                const qxProxy = {
                    tag: proxy.name,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.port,
                    uuid: proxy.uuid,
                    password: proxy.password, // For trojan/shadowsocks if present
                    method: proxy.cipher,
                    "alter-id": proxy.alterId,
                    "udp-relay": proxy.udp,
                    "skip-cert-verify": proxy['skip-cert-verify'],
                    "server-name": proxy.servername,
                    obfs: proxy.network === 'ws' ? 'ws' : undefined,
                    "obfs-path": proxy['ws-opts'] ? proxy['ws-opts'].path : undefined,
                    "obfs-header": proxy['ws-opts'] && proxy['ws-opts'].headers && proxy['ws-opts'].headers.Host ? `Host: ${proxy['ws-opts'].headers.Host}` : undefined,
                    // Add other types like ss, trojan, etc. if needed and map their parameters
                };

                // Remove undefined values
                Object.keys(qxProxy).forEach(key => qxProxy[key] === undefined && delete qxProxy[key]);

                result.proxies.push(qxProxy);
            } catch (e) {
                console.error("Error parsing proxy line:", trimmedLine, e);
            }
        } else if (inProxyGroup && trimmedLine.startsWith('- name:')) {
             // This is a proxy group definition
            try {
                // Simple parsing for groups, assumes simple key-value pairs
                const groupNameMatch = trimmedLine.match(/- name:\s*(.*)/);
                if (groupNameMatch) {
                    const group = { name: groupNameMatch[1].trim() };
                    // Read next lines for type and proxies
                    let i = lines.indexOf(line) + 1;
                    while (i < lines.length && lines[i].trim().startsWith('type:')) {
                        const typeMatch = lines[i].trim().match(/type:\s*(.*)/);
                        if (typeMatch) group.type = typeMatch[1].trim();
                        i++;
                        break; // Assuming type is on the next line
                    }
                    while (i < lines.length && lines[i].trim().startsWith('proxies:')) {
                        let j = i + 1;
                        group.proxies = [];
                        while (j < lines.length && lines[j].trim().startsWith('- ')) {
                            group.proxies.push(lines[j].trim().substring(2).trim());
                            j++;
                        }
                        i = j;
                        break;
                    }
                    result['proxy-groups'].push(group);
                }
            } catch (e) {
                console.error("Error parsing proxy group line:", trimmedLine, e);
            }
        }
    }
    return result;
}

// Main function for Quantumult X
async function parse() {
    const url = $resource.parameter;
    if (!url) {
        $done({});
        return;
    }

    try {
        const response = await $task.fetch({ url: url, method: 'GET' });
        const yamlContent = response.body;
        const parsedData = parseYaml(yamlContent);

        const qxConfig = {};

        // Convert proxies to Quantumult X format
        if (parsedData.proxies && parsedData.proxies.length > 0) {
            qxConfig.proxies = parsedData.proxies.map(p => {
                const qxStringParts = [`${p.type}=${p.server}:${p.port}`];
                if (p.uuid) qxStringParts.push(`uuid=${p.uuid}`);
                if (p.password) qxStringParts.push(`password=${p.password}`);
                if (p.method) qxStringParts.push(`method=${p.method}`);
                if (p['alter-id'] !== undefined) qxStringParts.push(`alter-id=${p['alter-id']}`);
                if (p['udp-relay'] !== undefined) qxStringParts.push(`udp-relay=${p['udp-relay'] ? 'true' : 'false'}`);
                if (p['skip-cert-verify'] !== undefined) qxStringParts.push(`skip-cert-verify=${p['skip-cert-verify'] ? 'true' : 'false'}`);
                if (p['server-name']) qxStringParts.push(`server-name=${p['server-name']}`);
                if (p.obfs) qxStringParts.push(`obfs=${p.obfs}`);
                if (p['obfs-path']) qxStringParts.push(`obfs-path=${p['obfs-path']}`);
                if (p['obfs-header']) qxStringParts.push(`obfs-header=${p['obfs-header']}`);
                if (p.tag) qxStringParts.push(`tag=${p.tag}`);
                return qxStringParts.join(', ');
            });
        }

        // Convert proxy-groups to Quantumult X format
        if (parsedData['proxy-groups'] && parsedData['proxy-groups'].length > 0) {
            qxConfig['proxy_groups'] = parsedData['proxy-groups'].map(group => {
                const groupParts = [`${group.type}=${group.name}`];
                if (group.proxies && group.proxies.length > 0) {
                    groupParts.push(`\n  ${group.proxies.join(', ')}`); // Indent proxies under group
                }
                return groupParts.join(', ');
            });
        }

        // Add rules if they exist in the YAML
        // This part needs more robust parsing if rules are complex.
        // For simplicity, we'll assume they are IP-CIDR,DIRECT style.
        const rules = [];
        const rulePrefix = 'IP-CIDR,';
        const globalDirectTag = '🎯 全球直连'; // Assuming this is a predefined tag in QX

        // A simple way to extract rules starting with 'IP-CIDR'
        const yamlLines = yamlContent.split('\n');
        for (const line of yamlLines) {
            const trimmedLine = line.trim();
            if (trimmedLine.startsWith(rulePrefix)) {
                // Example: IP-CIDR,103.72.12.0/22,🎯 全球直连,no-resolve
                const parts = trimmedLine.split(',');
                if (parts.length >= 3) {
                    const cidr = parts[1].trim();
                    const action = parts[2].trim(); // This will be "🎯 全球直连"
                    // Quantumult X rules format: IP-CIDR,xxx.xxx.xxx.xxx/xx,ProxyTag
                    rules.push(`IP-CIDR,${cidr},${action}`);
                }
            }
        }
        if (rules.length > 0) {
            qxConfig.rules = rules;
        }

        $done(qxConfig);

    } catch (error) {
        console.error("Error fetching or parsing resource:", error);
        $done({});
    }
}

parse();
