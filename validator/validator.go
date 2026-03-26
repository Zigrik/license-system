package validator

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LicenseData структура данных лицензии
type LicenseData struct {
	Company   string    `json:"company"`
	Product   string    `json:"product"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Validate проверяет лицензию
// decryptKeyPath: путь к файлу с ключом дешифрования (decrypt.key)
// licenseKeyPath: путь к файлу лицензии (например, license.key)
// productName: название продукта для проверки
// Возвращает: (valid bool, companyName string, err error)
func Validate(decryptKeyPath, licenseKeyPath, productName string) (bool, string, error) {
	// 1. Читаем ключ дешифрования
	keyData, err := os.ReadFile(decryptKeyPath)
	if err != nil {
		return false, "", fmt.Errorf("не найден файл ключа дешифрования: %w", err)
	}

	// Декодируем ключ из base64
	masterKey, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return false, "", fmt.Errorf("ошибка декодирования ключа: %w", err)
	}

	if len(masterKey) != 32 {
		return false, "", fmt.Errorf("неверный размер ключа: %d (должен быть 32)", len(masterKey))
	}

	// 2. Читаем файл лицензии
	licenseData, err := os.ReadFile(licenseKeyPath)
	if err != nil {
		return false, "", fmt.Errorf("не найден файл лицензии: %w", err)
	}

	// 3. Расшифровываем лицензию
	license, err := decrypt(string(licenseData), masterKey)
	if err != nil {
		return false, "", fmt.Errorf("ошибка расшифровки лицензии: %w", err)
	}

	// 4. Проверяем название продукта
	if license.Product != productName {
		return false, "", fmt.Errorf("лицензия предназначена для другого продукта: %s (ожидался %s)", license.Product, productName)
	}

	// 5. Проверяем срок действия
	if time.Now().After(license.ExpiresAt) {
		return false, "", fmt.Errorf("срок действия лицензии истек %s", license.ExpiresAt.Format("02.01.2006"))
	}

	// Все проверки пройдены
	return true, license.Company, nil
}

// decrypt расшифровывает лицензию
func decrypt(encrypted string, key []byte) (*LicenseData, error) {
	// Декодируем из base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования base64: %w", err)
	}

	// Создаем AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания cipher: %w", err)
	}

	// Создаем GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Получаем nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("некорректные данные")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]

	// Расшифровываем
	decrypted, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	// Парсим JSON
	var license LicenseData
	if err := json.Unmarshal(decrypted, &license); err != nil {
		return nil, fmt.Errorf("ошибка парсинга JSON: %w", err)
	}

	return &license, nil
}
