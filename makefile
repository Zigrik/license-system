.PHONY: build-genkey build-example clean generate-license help

# Сборка генератора
build-genkey:
	cd genkey && go build -o ../genkey

# Сборка примера
build-example:
	cd example && go build -o ../example

# Генерация тестовой лицензии
generate-license: build-genkey
	./genkey -company="ООО Ромашка" -product="OZON Api Cabinet" -days=30

# Очистка
clean:
	rm -f genkey example decrypt.key *.key

# Помощь
help:
	@echo "Доступные команды:"
	@echo "  make build-genkey       - Собрать генератор ключей"
	@echo "  make build-example      - Собрать пример программы"
	@echo "  make generate-license   - Сгенерировать тестовую лицензию"
	@echo "  make clean              - Очистить"