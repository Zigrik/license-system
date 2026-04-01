package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// LicenseData структура данных лицензии
type LicenseData struct {
	Company   string    `json:"company"`
	Product   string    `json:"product"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	// Загружаем .env
	env, err := loadEnv(".env")
	if err != nil {
		fmt.Println("❌ Ошибка: файл .env не найден")
		fmt.Println("Создайте файл .env из .env.example")
		os.Exit(1)
	}

	// Получаем мастер-ключ
	masterKeyB64 := env["MASTER_KEY"]
	if masterKeyB64 == "" {
		fmt.Println("❌ Ошибка: MASTER_KEY не задан в .env")
		os.Exit(1)
	}

	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil || len(masterKey) != 32 {
		fmt.Println("❌ Ошибка: MASTER_KEY должен быть 32 байта в base64")
		fmt.Println("Сгенерируйте: openssl rand -base64 32")
		os.Exit(1)
	}

	// Получаем список продуктов
	var products []string
	productsJSON := env["PRODUCTS"]
	if productsJSON == "" {
		fmt.Println("❌ Ошибка: PRODUCTS не задан в .env")
		os.Exit(1)
	}
	if err := json.Unmarshal([]byte(productsJSON), &products); err != nil {
		fmt.Println("❌ Ошибка: неверный формат PRODUCTS")
		os.Exit(1)
	}

	// Парсим аргументы
	var (
		company = flag.String("company", "", "Название компании")
		product = flag.String("product", "", "Название продукта")
		days    = flag.Int("days", 30, "Срок действия в днях")
	)
	flag.Parse()

	// Проверяем обязательные поля
	if *company == "" {
		fmt.Println("❌ Ошибка: не указана компания (-company)")
		flag.Usage()
		os.Exit(1)
	}

	if *product == "" {
		fmt.Println("\n❌ Ошибка: не указан продукт (-product)")
		fmt.Println("Доступные продукты:")
		for _, p := range products {
			fmt.Printf("  - %s\n", p)
		}
		os.Exit(1)
	}

	// Проверяем, существует ли продукт
	productExists := false
	for _, p := range products {
		if p == *product {
			productExists = true
			break
		}
	}
	if !productExists {
		fmt.Printf("❌ Ошибка: продукт '%s' не найден\n", *product)
		fmt.Println("\nДоступные продукты:")
		for _, p := range products {
			fmt.Printf("  - %s\n", p)
		}
		os.Exit(1)
	}

	// Создаем данные лицензии
	license := LicenseData{
		Company:   *company,
		Product:   *product,
		ExpiresAt: time.Now().Add(time.Duration(*days) * 24 * time.Hour),
	}

	// Шифруем
	encrypted, err := encrypt(license, masterKey)
	if err != nil {
		fmt.Printf("❌ Ошибка шифрования: %v\n", err)
		os.Exit(1)
	}

	// Сохраняем файл лицензии
	licenseFilename := fmt.Sprintf("%s_%s.key", *company, *product)
	if err := os.WriteFile(licenseFilename, []byte(encrypted), 0644); err != nil {
		fmt.Printf("❌ Ошибка сохранения: %v\n", err)
		os.Exit(1)
	}

	// Сохраняем ключ дешифрования
	decryptKeyFile := "decrypt.key"
	if err := os.WriteFile(decryptKeyFile, []byte(masterKeyB64), 0644); err != nil {
		fmt.Printf("❌ Ошибка сохранения ключа: %v\n", err)
		os.Exit(1)
	}

	// Выводим информацию
	fmt.Println("\n✅ ЛИЦЕНЗИЯ СОЗДАНА")
	fmt.Println("=================================")
	fmt.Printf("Компания:    %s\n", license.Company)
	fmt.Printf("Продукт:     %s\n", license.Product)
	fmt.Printf("Действительна до: %s\n", license.ExpiresAt.Format("02.01.2006"))
	fmt.Printf("Осталось дней: %d\n", *days)
	fmt.Println("=================================")
	fmt.Printf("📄 Файл лицензии: %s\n", licenseFilename)
	fmt.Printf("🔑 Файл ключа дешифрования: %s\n", decryptKeyFile)
	fmt.Println("\n📌 Инструкция:")
	fmt.Printf("1. Передайте клиенту файл: %s\n", licenseFilename)
	fmt.Printf("2. Файл %s встройте в свою программу\n", decryptKeyFile)
}

// loadEnv загружает .env файл
func loadEnv(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		env[key] = value
	}

	return env, scanner.Err()
}

// encrypt шифрует данные
func encrypt(data LicenseData, key []byte) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, jsonData, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
