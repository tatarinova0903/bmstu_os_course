# Операционные системы
## Курсовая работа

### Тема

Загружаемый модуль ядра для ОС Linux, позволяющий скрывать файлы или запрещать их изменение, чтение и удаление.

### Задание

Разработать загружаемый модуль ядра для ОС Linux, позволяющий скрывать файлы или запрещать их изменение, чтение и удаление. Предусмотреть возможность ввода пароля для отображения файлов или разрешения операций над ними. Предоставить пользователю возможность задавать список таких файлов.

## hidden file

```bash
$ echo hiddent.txt > hidden // в /proc

$ touch hidden.txt
$ ls
-- no results--
$ echo "1234" > /dev/usb15
$ ls
hidden.txt
$ echo "1234" > /dev/usb15
$ ls
-- no results--
```

## protected file

```bash
$ ls
test.txt protected.txt
$ rm protected.txt
$ ls 
test.txt protected.txt
$ echo "5678" > /dev/usb15     
$ rm protected.txt
$ ls
test.txt
```
