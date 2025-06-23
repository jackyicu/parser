/**
 * Clash配置文件转Quantumult X解析器
 * 适用于Quantumult X的资源解析器
 */

// 解析器入口函数
function parseClashConfig(rawContent) {
    try {
        // 解析YAML格式的Clash配置
        const config = parseYAML(rawContent);
        
        if (!config || !config.proxies) {
            throw new Error('无效的Clash配置文件');
        }
        
        const nodes = [];
        
        // 遍历所有代理节点
        for (const proxy of config.proxies) {
            const node = convertProxyToQuantumult(proxy);
            if (node) {
                nodes.push(node);
            }
        }
        
        return nodes.join('\n');
        
    } catch (error) {
        console.log(`解析错误: ${error.message}`);
        return '';
    }
}

// 简化的YAML解析器（针对Clash配置）
function parseYAML(content) {
    const config = {
        proxies: []
    };
    
    const lines = content.split('\n');
    let currentSection = null;
    let currentProxy = null;
    
    for (let line of lines) {
        line = line.trim();
        
        if (line.startsWith('#') || line === '') continue;
        
        // 检测section
        if (line === 'proxies:') {
            currentSection = 'proxies';
            continue;
        }
        
        if (currentSection === 'proxies') {
            if (line.startsWith('- name:')) {
                // 保存上一个代理
                if (currentProxy) {
                    config.proxies.push(currentProxy);
                }
                // 开始新代理
                currentProxy = {};
                const nameMatch = line.match(/- name:\s*["']?([^"']+)["']?/);
                if (nameMatch) {
                    currentProxy.name = nameMatch[1];
                }
            } else if (currentProxy && line.includes(':')) {
                const [key, ...valueParts] = line.split(':');
                const value = valueParts.join(':').trim().replace(/["']/g, '');
                
                switch (key.trim()) {
                    case 'type':
                        currentProxy.type = value;
                        break;
                    case 'server':
                        currentProxy.server = value;
                        break;
                    case 'port':
                        currentProxy.port = parseInt(value);
                        break;
                    case 'password':
                        currentProxy.password = value;
                        break;
                    case 'cipher':
                    case 'method':
                        currentProxy.cipher = value;
                        break;
                    case 'uuid':
                        currentProxy.uuid = value;
                        break;
                    case 'alterId':
                    case 'alter-id':
                        currentProxy.alterId = parseInt(value);
                        break;
                    case 'network':
                        currentProxy.network = value;
                        break;
                    case 'ws-path':
                    case 'path':
                        currentProxy.path = value;
                        break;
                    case 'ws-headers':
                    case 'headers':
                        if (value.includes('Host:')) {
                            const hostMatch = value.match(/Host:\s*([^,}]+)/);
                            if (hostMatch) {
                                currentProxy.host = hostMatch[1].trim();
                            }
                        }
                        break;
                    case 'tls':
                        currentProxy.tls = value === 'true';
                        break;
                    case 'skip-cert-verify':
                        currentProxy.skipCertVerify = value === 'true';
                        break;
                    case 'sni':
                        currentProxy.sni = value;
                        break;
                }
            }
        } else {
            // 其他section，重置currentSection
            if (line.endsWith(':') && !line.includes(' ')) {
                currentSection = null;
                currentProxy = null;
            }
        }
    }
    
    // 添加最后一个代理
    if (currentProxy) {
        config.proxies.push(currentProxy);
    }
    
    return config;
}

// 将Clash代理转换为Quantumult X格式
function convertProxyToQuantumult(proxy) {
    if (!proxy.name || !proxy.server || !proxy.port) {
        return null;
    }
    
    const tag = proxy.name;
    const server = proxy.server;
    const port = proxy.port;
    
    switch (proxy.type) {
        case 'ss':
        case 'shadowsocks':
            return convertShadowsocks(proxy);
            
        case 'ssr':
        case 'shadowsocksr':
            return convertShadowsocksR(proxy);
            
        case 'vmess':
            return convertVmess(proxy);
            
        case 'trojan':
            return convertTrojan(proxy);
            
        case 'http':
        case 'https':
            return convertHttp(proxy);
            
        case 'socks5':
            return convertSocks5(proxy);
            
        default:
            console.log(`不支持的代理类型: ${proxy.type}`);
            return null;
    }
}

// Shadowsocks转换
function convertShadowsocks(proxy) {
    const method = proxy.cipher || proxy.method || 'aes-256-gcm';
    const password = proxy.password || '';
    
    let config = `shadowsocks=${proxy.server}:${proxy.port}`;
    config += `, method=${method}`;
    config += `, password=${password}`;
    
    if (proxy.plugin) {
        // 处理插件配置
        if (proxy.plugin === 'obfs') {
            config += `, obfs=${proxy['plugin-opts']?.mode || 'http'}`;
            if (proxy['plugin-opts']?.host) {
                config += `, obfs-host=${proxy['plugin-opts'].host}`;
            }
        }
    }
    
    config += `, tag=${proxy.name}`;
    
    if (proxy.udp !== false) {
        config += `, udp-relay=true`;
    }
    
    return config;
}

// ShadowsocksR转换
function convertShadowsocksR(proxy) {
    let config = `shadowsocks=${proxy.server}:${proxy.port}`;
    config += `, method=${proxy.cipher || 'aes-256-cfb'}`;
    config += `, password=${proxy.password || ''}`;
    config += `, ssr-protocol=${proxy.protocol || 'origin'}`;
    config += `, ssr-protocol-param=${proxy['protocol-param'] || ''}`;
    config += `, ssr-obfs=${proxy.obfs || 'plain'}`;
    config += `, ssr-obfs-param=${proxy['obfs-param'] || ''}`;
    config += `, tag=${proxy.name}`;
    
    return config;
}

// VMess转换
function convertVmess(proxy) {
    let config = `vmess=${proxy.server}:${proxy.port}`;
    config += `, method=${proxy.cipher || 'aes-128-gcm'}`;
    config += `, password=${proxy.uuid || ''}`;
    
    // WebSocket配置
    if (proxy.network === 'ws') {
        config += `, obfs=ws`;
        if (proxy.path) {
            config += `, obfs-uri=${proxy.path}`;
        }
        if (proxy.host || proxy['ws-headers']?.Host) {
            const host = proxy.host || proxy['ws-headers']?.Host;
            config += `, obfs-host=${host}`;
        }
    }
    
    // TLS配置
    if (proxy.tls) {
        config += `, tls=true`;
        if (proxy.sni) {
            config += `, tls-host=${proxy.sni}`;
        }
    }
    
    // 跳过证书验证
    if (proxy['skip-cert-verify']) {
        config += `, tls-verification=false`;
    }
    
    config += `, tag=${proxy.name}`;
    
    return config;
}

// Trojan转换
function convertTrojan(proxy) {
    let config = `trojan=${proxy.server}:${proxy.port}`;
    config += `, password=${proxy.password || ''}`;
    
    if (proxy.sni) {
        config += `, tls-host=${proxy.sni}`;
    }
    
    if (proxy['skip-cert-verify']) {
        config += `, tls-verification=false`;
    }
    
    config += `, tag=${proxy.name}`;
    
    return config;
}

// HTTP代理转换
function convertHttp(proxy) {
    let config = `http=${proxy.server}:${proxy.port}`;
    
    if (proxy.username && proxy.password) {
        config += `, username=${proxy.username}`;
        config += `, password=${proxy.password}`;
    }
    
    if (proxy.type === 'https' || proxy.tls) {
        config += `, over-tls=true`;
        if (proxy['skip-cert-verify']) {
            config += `, tls-verification=false`;
        }
    }
    
    config += `, tag=${proxy.name}`;
    
    return config;
}

// SOCKS5转换
function convertSocks5(proxy) {
    let config = `socks5=${proxy.server}:${proxy.port}`;
    
    if (proxy.username && proxy.password) {
        config += `, username=${proxy.username}`;
        config += `, password=${proxy.password}`;
    }
    
    config += `, tag=${proxy.name}`;
    
    return config;
}

// Quantumult X解析器接口
// 这是Quantumult X调用的主函数
var body = $response.body;
var parsedNodes = parseClashConfig(body);

// 返回解析结果
$done({
    body: parsedNodes
});
