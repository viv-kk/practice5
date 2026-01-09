echo "Сборка SIEM Agent"
if ! command -v cmake &> /dev/null; then
    echo "ERROR: cmake не установлен. Установите: sudo apt-get install cmake build-essential"
    exit 1
fi
mkdir -p build
cd build
echo "Конфигурация CMake..."
cmake ..

echo "Сборка siem_agent..."
make siem_agent

if [ $? -eq 0 ]; then
    echo "Проект собран"
    echo "Исполняемый файл: $(pwd)/siem_agent"
    if [ -f ../siem_config.json ]; then
        cp ../siem_config.json ./siem_config.json
        echo "Конфигурационный файл скопирован в build/"
    fi
    
    echo ""
    echo "Для запуска:"
    echo "  sudo ./build/siem_agent --config siem_config.json"
else
    echo "Ошибка сборки"
    exit 1
fi

