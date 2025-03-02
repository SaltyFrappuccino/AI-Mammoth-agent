import os
import PyInstaller.__main__
import shutil

# Создаем директорию для временных файлов, если она не существует
os.makedirs("build", exist_ok=True)
os.makedirs("dist", exist_ok=True)

# Определяем имя выходного .exe файла
output_exe_name = "AI-Mammoth-GUI"

# Запускаем PyInstaller с нужными параметрами
PyInstaller.__main__.run([
    'gui.py',                      # Имя входного файла
    '--name=%s' % output_exe_name, # Имя выходного файла
    '--onefile',                    # Создать один .exe файл
    '--windowed',                   # Не показывать консоль при запуске
    '--add-data=README.md;.',       # Добавить README.md в корень
    '--icon=NONE',                  # Иконка (замените на путь к вашему .ico файлу, если есть)
    '--clean',                      # Очистить кэш перед сборкой
    '--noconfirm',                  # Не спрашивать подтверждения на перезапись
    '--log-level=INFO',             # Уровень логирования
])

print(f"\nСборка завершена. Исполняемый файл находится в: dist/{output_exe_name}.exe") 