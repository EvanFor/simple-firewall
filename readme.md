# Simple Firewall 简单防火墙

一个基于Python实现的轻量级网络防火墙，提供基本的数据包过滤功能。

## 🚀 主要功能

- 数据包过滤和拦截
- 网络流量监控
- 规则配置管理
- Web管理界面
- 访问日志记录

## 📋 系统要求

- **Python**: 3.7+
- **操作系统**: Windows/Linux/macOS
- **依赖**: 第三方库(详见requirements.txt)

## 🔧 安装使用

```bash
# 克隆项目
git clone https://github.com/yourusername/simple-firewall.git
cd simple-firewall

# 安装依赖
pip install -r requirements.txt

# 运行防火墙
sudo python main.py

# 访问管理界面
# 浏览器打开: http://localhost:8081
```

## 🎯 快速开始

1. 安装依赖: `pip install -r requirements.txt`
2. 运行程序: `sudo python main.py`
3. 浏览器访问: `http://localhost:8081`
4. 配置过滤规则
5. 监控网络活动

## 🛠️ 功能说明

### 规则类型
- 允许/阻止规则
- 端口过滤
- IP地址过滤
- 协议过滤

### 监控功能
- 实时流量统计
- 连接状态监控
- 访问日志记录

## 📊 项目结构

```
simple-firewall/
├── main.py          # 主程序文件
├── index.html       # Web管理界面
├── requirements.txt # 依赖包列表
└── README.md        # 说明文档
```

## 🔒 注意事项

- 仅供学习测试使用
- 生产环境使用前请充分测试
- 需要管理员/root权限运行
- 建议定期备份配置规则

## 🐛 常见问题

**程序无法启动**: 检查系统权限和端口占用情况

**规则不生效**: 验证规则配置是否正确

**界面无法访问**: 确认防火墙未阻止本地访问



## 🤝 贡献

欢迎提交Issue和Pull Request来改进项目。

## 📄 许可证

MIT License

## 📞 联系

- GitHub: [项目地址]
- Issues: [问题反馈]

> ⚠️ 注意：此项目仅供学习测试使用