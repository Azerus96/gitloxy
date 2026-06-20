const express = require('express');
const proxy = require('express-http-proxy');
const app = express();
const PORT = process.env.PORT || 8080;

// Прокси для CDN статики GitLab
app.use('/_assets_static_', proxy('https://assets.gitlab-static.net', {
  proxyReqOptDecorator: function(proxyReqOpts, srcReq) {
    proxyReqOpts.headers['Host'] = 'assets.gitlab-static.net';
    proxyReqOpts.headers['accept-encoding'] = 'gzip'; // Ограничиваем сжатие до gzip для корректной распаковки
    return proxyReqOpts;
  },
  userResHeaderDecorator(headers) {
    // Удаляем политики безопасности, которые могут блокировать загрузку ассетов браузером
    delete headers['content-security-policy'];
    delete headers['content-security-policy-report-only'];
    return headers;
  }
}));

// Основной прокси для gitlab.com
app.use('/', proxy('https://gitlab.com', {
  proxyReqOptDecorator: function(proxyReqOpts, srcReq) {
    proxyReqOpts.headers['Host'] = 'gitlab.com';
    proxyReqOpts.headers['accept-encoding'] = 'gzip'; // Избегаем сжатия Brotli
    
    // Скрываем российские IP-адреса, удаляя проброшенные заголовки
    delete proxyReqOpts.headers['x-forwarded-for'];
    delete proxyReqOpts.headers['x-real-ip'];
    return proxyReqOpts;
  },

  userResHeaderDecorator(headers, userReq) {
    const myHost = userReq.headers.host;

    // Переписываем редиректы, чтобы телефон оставался на вашем домене Render
    if (headers.location && headers.location.includes('gitlab.com')) {
      headers.location = headers.location.replace('https://gitlab.com', `https://${myHost}`);
    }

    // Корректируем куки для успешной авторизации и удержания сессии
    if (headers['set-cookie']) {
      const myHostWithoutPort = myHost.split(':')[0];
      headers['set-cookie'] = headers['set-cookie'].map(cookie => {
        return cookie
          .replace(/domain=\.?gitlab\.com/gi, `domain=.${myHostWithoutPort}`)
          .replace(/SameSite=None/gi, 'SameSite=Lax');
      });
    }

    // Удаляем заголовки безопасности, мешающие работе прокси на стороннем домене
    delete headers['content-security-policy'];
    delete headers['content-security-policy-report-only'];
    delete headers['x-frame-options'];
    delete headers['strict-transport-security'];

    return headers;
  },

  userResDecorator: function(proxyRes, proxyResData, userReq) {
    const contentType = proxyRes.headers['content-type'] || '';
    if (contentType.includes('text/html')) {
      let html = proxyResData.toString('utf8');
      const myHost = userReq.headers.host;
      
      // Перенаправляем абсолютные ссылки на статику через наш прокси-маршрут
      html = html.replace(/https:\/\/assets\.gitlab-static\.net/g, `https://${myHost}/_assets_static_`);
      
      // Заменяем абсолютные ссылки gitlab.com на адрес вашего прокси
      html = html.replace(/https:\/\/gitlab\.com/g, `https://${myHost}`);
      return html;
    }
    return proxyResData;
  }
}));

app.listen(PORT, () => {
  console.log(`GitLab proxy running on port ${PORT}`);
});
