Видно, что первый сервис формирует HTTP запрос ко второму самостоятельно, не экранируя при этом каким-либо образом параметр username. То есть, мы можем сформировать некорректный запрос, получив тем самым сообщение об ошибке, в котором будет содержаться флаг.

Пример запроса: 
```http
POST /register
username=%0A&password=qq
```


Флаг: `NTO{request_smuggling_917a34072663f9c8beea3b45e8f129c5}`