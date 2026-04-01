package license

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LicenseData структура данных из ключа
type LicenseData struct {
	Company   string    `json:"company"`
	Product   string    `json:"product"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CheckResult результат проверки
type CheckResult struct {
	Valid   bool   // true - лицензия валидна, false - не валидна
	Company string // название компании (если лицензия валидна)
	Error   string // описание ошибки (если не валидна)
}

// CheckLicenseFromFile проверяет лицензию из файла
// Параметры:
//   - decryptKey: ключ дешифрования (строка в base64)
//   - licenseKeyPath: путь к файлу лицензии
//   - expectedProduct: ожидаемое название продукта
//
// Возвращает:
//   - CheckResult: результат проверки
func CheckLicense(decryptKeyB64, licenseKeyPath, expectedProduct string) CheckResult {
	// 1. Читаем файл лицензии
	licenseData, err := os.ReadFile(licenseKeyPath)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Файл лицензии не найден: %s", licenseKeyPath),
		}
	}

	return CheckLicenseFromBytes(decryptKeyB64, string(licenseData), expectedProduct)
}

// CheckLicenseFromBytes проверяет лицензию из строки (для встроенного ключа)
// Параметры:
//   - decryptKeyB64: ключ дешифрования (строка в base64)
//   - licenseKey: содержимое файла лицензии (строка)
//   - expectedProduct: ожидаемое название продукта
//
// Возвращает:
//   - CheckResult: результат проверки
func CheckLicenseFromBytes(decryptKeyB64, licenseKey, expectedProduct string) CheckResult {
	// 1. Декодируем ключ дешифрования
	masterKey, err := base64.StdEncoding.DecodeString(decryptKeyB64)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: "Ошибка декодирования ключа дешифрования",
		}
	}

	if len(masterKey) != 32 {
		return CheckResult{
			Valid: false,
			Error: "Неверный размер ключа дешифрования (должен быть 32 байта)",
		}
	}

	// 2. Расшифровываем лицензию
	license, err := decrypt(licenseKey, masterKey)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: "Ошибка расшифровки лицензии. Возможно, файл поврежден",
		}
	}

	// 3. Проверяем название продукта
	if license.Product != expectedProduct {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Неверный продукт. Ожидается: %s, В лицензии: %s", expectedProduct, license.Product),
		}
	}

	// 4. Проверяем срок действия
	if time.Now().After(license.ExpiresAt) {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Срок действия лицензии истек %s", license.ExpiresAt.Format("02.01.2006")),
		}
	}

	// Всё хорошо
	return CheckResult{
		Valid:   true,
		Company: license.Company,
		Error:   "",
	}
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
