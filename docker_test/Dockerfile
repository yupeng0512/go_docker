FROM golang:1.21-alpine AS builder
LABEL authors="yupeng"

# 移动到工作目录：/build
WORKDIR /build

# 将代码复制到容器中
COPY go.mod .
COPY go.sum .
COPY . .

# 将我们的代码编译成二进制可执行文件app
RUN go env -w GOPROXY=https://goproxy.io,direct
RUN go build -o main .

# 移动到用于存放生成的二进制文件的 /dist 目录
WORKDIR /dist

# 将二进制文件从 /build 目录复制到这里
RUN cp /build/main .

# 声明服务端口
EXPOSE 8888

# 启动容器时运行的命令
CMD ["/dist/main"]

