package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
)

// 对称加密密钥，注意保密性
var key []byte

// 加载配置文件
func loadConfig() {
	viper.SetConfigName("config")   // 配置文件名（无文件扩展名）
	viper.AddConfigPath("./config") // 配置文件路径，此处为当前目录

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("failed to read config file: %s", err))
	}

	// 从配置文件中读取密钥
	keyString := viper.GetString("encryption.key")
	key = []byte(keyString)
}

// 传入原始文件对称加密，返回文件地址的路由处理函数
func encryptFileHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	//打开原始文件
	srcFile, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer func(srcFile multipart.File) {
		err := srcFile.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}(srcFile)

	// 创建加密后的文件
	filePath := "./attachment/encrypt_file/"
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err = os.MkdirAll(filePath, os.ModePerm)
	}
	encryptedFilePath := filePath + fmt.Sprintf("file_%d", rand.Intn(1000000))
	encryptedFile, err := os.Create(encryptedFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer func(encryptedFile *os.File) {
		err := encryptedFile.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}(encryptedFile)

	// 创建加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	stream := cipher.NewCFBEncrypter(block, key)

	// 加密并写入加密文件
	writer := &cipher.StreamWriter{S: stream, W: encryptedFile}
	if _, err := io.Copy(writer, srcFile); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"encryptedFile": encryptedFilePath})
}

// 传入加密后文件，解密后向浏览器输出原始格式的二进制流的路由处理函数
func decryptFileHandlerByPost(c *gin.Context) {
	file, _ := c.FormFile("encryptedFile")

	// 打开加密文件
	encryptedFile, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer func(encryptedFile multipart.File) {
		err := encryptedFile.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}(encryptedFile)

	// 创建解密器
	block, err := aes.NewCipher(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	stream := cipher.NewCFBDecrypter(block, key)

	// 创建解密后的文件
	decryptedFile, err := os.Create("./attachment/decrypt_file/" + file.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer func(decryptedFile *os.File) {
		err := decryptedFile.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}(decryptedFile)

	// 解密并写入解密文件
	reader := &cipher.StreamReader{S: stream, R: encryptedFile}
	if _, err := io.Copy(decryptedFile, reader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 设置响应头，指定Content-Type为二进制流
	c.Header("Content-Type", "application/octet-stream")
	c.File("./attachment/decrypt_file/" + file.Filename)
}

func main() {
	loadConfig()
	router := gin.Default()

	// 设置路由
	router.POST("/encrypt", encryptFileHandler)
	router.POST("/post-decrypt", decryptFileHandlerByPost)
	router.GET("/get-decrypt", decryptFileHandlerByGet)
	// 启动服务器
	router.Run(":8888")
}

// 传入加密后文件地址和原始文件名，解密后向浏览器输出原始格式的二进制流的路由处理函数
func decryptFileHandlerByGet(c *gin.Context) {
	// 从请求参数中获取加密后文件地址
	encryptedFilePath := c.Query("encryptedFilePath")
	//从请求参数中获取原始文件名+类型
	decryptedFileName := c.Query("decryptedFileName")
	//打开加密文件
	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 创建解密器
	block, err := aes.NewCipher(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	stream := cipher.NewCFBDecrypter(block, key)

	// 创建解密后的文件
	decryptedFile, err := os.Create("./attachment/decrypt_file/" + decryptedFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer func(decryptedFile *os.File) {
		err := decryptedFile.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}(decryptedFile)

	// 解密并写入解密文件
	reader := &cipher.StreamReader{S: stream, R: encryptedFile}
	if _, err := io.Copy(decryptedFile, reader); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fileData, err := io.ReadAll(decryptedFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 设置响应头，指定Content-Type为二进制流
	c.Header("Content-Type", "application/octet-stream")
	c.Data(http.StatusOK, "application/octet-stream", fileData)
}
