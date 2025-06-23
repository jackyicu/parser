/**
 * 简化版 Clash 到 Quantumult X 解析器
 * 专门处理 result type error 问题
 */

// 主解析函数
function parseClash(content) {
    var result = [];
    
    try {
        if (!content) {
            return "";
        }
        
        // 按行分割
        var lines = content.split('\n');
        var inProxies = false;
        var currentProxy = {};
        
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            
            // 去掉首尾空格
            line = line.replace(/^\s+|\s+$/g, '');
            
            // 跳过注释和空行
            if (!line || line.charAt(0) === '#') {
                continue;
            }
            
            // 检测是否进入proxies部分
            if (line === 'proxies:') {
                inProxies = true;
                continue;
            }
            
            // 如果遇到其他顶级配置，退出proxies部分
            if (inProxies && line.charAt(line.length - 1) === ':' && line.indexOf(' ') === -1) {
                inProxies = false;
                continue;
            }
            
            if (inProxies) {
                // 新的代理开始
                if (line.indexOf('- name:') === 0) {
                    // 处理上一个代理
                    if (currentProxy.name) {
                        var converted = convertProxy(currentProxy);
                        if (converted) {
                            result.push(converted);
                        }
                    }
                    
                    // 开始新代理
                    currentProxy = {};
                    var nameMatch = line.match(/name:\s*(.+)/);
                    if (nameMatch) {
                        currentProxy.name = nameMatch[1].replace(/['"]/g, '');
                    }
                }
                else if (line.indexOf(':') > 0) {
                    // 解析属性
                    var parts = line.split(':');
                    if (parts.length >= 2) {
                        var key = parts[0].replace(/^\s+|\s+$/g, '');
                        var value = parts.slice(1).join(':').replace(/^\s+|\s+$/g, '').replace(/['"]/g, '');
                        
                        currentProxy[key] = value;
                    }
                }
            }
        }
        
        // 处理最后一个代理
        if (currentProxy.name) {
            var converted = convertProxy(currentProxy);
            if (converted) {
                result.push(converted);
            }
        }
        
    } catch (e) {
        console.log('解析出错: ' + e.toString());
    }
    
    return result.join('\n');
}

// 转换代理配置
function convertProxy(proxy) {
    if (!proxy.name || !proxy.server || !proxy.port || !proxy.type) {
        return null;
    }
    
    var config = '';
    
    try {
        switch (proxy.type) {
            case 'ss':
            case 'shadowsocks':
                config = 'shadowsocks=' + proxy.server + ':' + proxy.port;
                config += ', method=' + (proxy.cipher || proxy.method || 'aes-256-gcm');
                config += ', password=' + (proxy.password || '');
                config += ', tag=' + proxy.name;
                break;
                
            case 'vmess':
                config = 'vmess=' + proxy.server + ':' + proxy.port;
                config += ', method=' + (proxy.cipher || 'aes-128-gcm');
                config += ', password=' + (proxy.uuid || '');
                
                if (proxy.network === 'ws') {
                    config += ', obfs=ws';
                    if (proxy.path || proxy['ws-path']) {
                        config += ', obfs-uri=' + (proxy.path || proxy['ws-path']);
                    }
                    if (proxy.host) {
                        config += ', obfs-host=' + proxy.host;
                    }
                }
                
                if (proxy.tls === 'true' || proxy.tls === true) {
                    config += ', tls=true';
                    if (proxy.sni) {
                        config += ', tls-host=' + proxy.sni;
                    }
                }
                
                config += ', tag=' + proxy.name;
                break;
                
            case 'trojan':
                config = 'trojan=' + proxy.server + ':' + proxy.port;
                config += ', password=' + (proxy.password || '');
                if (proxy.sni) {
                    config += ', tls-host=' + proxy.sni;
                }
                config += ', tag=' + proxy.name;
                break;
                
            case 'http':
            case 'https':
                config = 'http=' + proxy.server + ':' + proxy.port;
                if (proxy.username && proxy.password) {
                    config += ', username=' + proxy.username;
                    config += ', password=' + proxy.password;
                }
                if (proxy.type === 'https' || proxy.tls === 'true') {
                    config += ', over-tls=true';
                }
                config += ', tag=' + proxy.name;
                break;
                
            case 'socks5':
                config = 'socks5=' + proxy.server + ':' + proxy.port;
                if (proxy.username && proxy.password) {
                    config += ', username=' + proxy.username;
                    config += ', password=' + proxy.password;
                }
                config += ', tag=' + proxy.name;
                break;
                
            default:
                return null;
        }
        
    } catch (e) {
        console.log('转换代理出错: ' + e.toString());
        return null;
    }
    
    return config;
}

// Quantumult X 入口点
var content = $response.body || '';
var converted = parseClash(content);

$done({
    body: converted
});
