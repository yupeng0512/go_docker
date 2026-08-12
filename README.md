# go_docker

## docker_test

运行服务前，通过进程环境提供 legacy AES-128 key；必须恰好是 16 字节：

```bash
cd docker_test
ENCRYPTION_KEY='<从个人秘密存储注入>' go run .
```

仓库中的 `docker_test/config/config.yaml` 仅保留无密占位，不存放可用 key。

这是兼容旧文件格式的实验服务，不应直接用于生产或敏感数据。旧实现曾把加密材料提交到
公开历史，并使用缺少认证保护的 legacy CFB 格式；当前提交只阻止继续泄露和误用旧 key，
不宣称旧密文仍具保密性。升级到随机 nonce 的认证加密前，项目不应进入一键恢复或生产部署。
