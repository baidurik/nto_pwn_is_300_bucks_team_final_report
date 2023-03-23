Готовый эксплоит: [solve.py](solve.py)

Нам предоставлена возможность совершать prototype pollution по адресу /pollute/key/value

Покопавшись в коде, понимаем, что можем передавать дополнительные параметры в функцию `passport.authenticate` (index.js строки 48-52)

```js
app.get("/auth", passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/error',
    failureMessage: true
}))
```

Посмотрев на список возможных параметров `AuthenticateOptions`, находим интересное поле `userProperty`, которое позволяет нам изменять объект `req`. Заменим это свойство на `isLocalRequest`, чтобы обмануть проверку в index.js:61. Однако этого мало, ведь при новом запросе создастся новый объект `req`, так что копнув глубже, мы можем обнаружить, что мы можем указать страницу, на которую мы хотим попасть после авторизации, для этого должно присутствовать поле `returnTo` у объекта `req.session` (authenticate.js:260-267)

```js
if (options.successReturnToOrRedirect) {
    var url = options.successReturnToOrRedirect;
    if (req.session && req.session.returnTo) {
        url = req.session.returnTo;
        delete req.session.returnTo;
    }
    return res.redirect(url);
}
```

Используя prototype pollution, устанавливаем значение этого поля в `'/admin/flag'` и получаем флаг: `nto{pr0t0typ3_pollut10n_g4dged5_f56acc00f5eb803de88496b}`