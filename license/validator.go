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

// CheckLicense проверяет лицензию
// Параметры:
//   - decryptKeyPath: путь к файлу decrypt.key
//   - licenseKeyPath: путь к файлу лицензии (license.key)
//   - expectedProduct: ожидаемое название продукта
//
// Возвращает:
//   - CheckResult: результат проверки
func CheckLicense(decryptKeyPath, licenseKeyPath, expectedProduct string) CheckResult {
	// 1. Читаем ключ дешифрования
	keyData, err := os.ReadFile(decryptKeyPath)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Файл ключа дешифрования не найден: %s", decryptKeyPath),
		}
	}

	// Декодируем ключ из base64
	masterKey, err := base64.StdEncoding.DecodeString(string(keyData))
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

	// 2. Читаем файл лицензии
	licenseData, err := os.ReadFile(licenseKeyPath)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Файл лицензии не найден: %s", licenseKeyPath),
		}
	}

	// 3. Расшифровываем лицензию
	license, err := decrypt(string(licenseData), masterKey)
	if err != nil {
		return CheckResult{
			Valid: false,
			Error: "Ошибка расшифровки лицензии. Возможно, файл поврежден",
		}
	}

	// 4. Проверяем название продукта
	if license.Product != expectedProduct {
		return CheckResult{
			Valid: false,
			Error: fmt.Sprintf("Неверный продукт. Ожидается: %s, В лицензии: %s", expectedProduct, license.Product),
		}
	}

	// 5. Проверяем срок действия
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
