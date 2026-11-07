# SIXVOID APIS — instalação e publicação

## O que foi atualizado

- Identidade visual SIXVOID em preto/roxo.
- Menu lateral expansível pelo botão de três linhas.
- Página pública com documentação, verificação de API Key e acesso à solicitação de chaves.
- Página de solicitação de nova chave ou recarga: envia os dados ao WhatsApp do proprietário; não libera chaves automaticamente.
- Painel administrativo com login, estatísticas reais, geração de chave, listagem, cópia, recarga e exclusão.
- Rotas antigas de adicionar/remover chave por GET foram desativadas.
- Contagem persistente de requisições em `lib/secret/metrics.json`.
- Servidor escuta em `0.0.0.0` e usa `process.env.PORT`, pronto para hospedagem Node.

## Configuração local

1. Instale Node.js 18 ou superior.
2. Na pasta do projeto, instale as dependências:

   ```bash
   npm install
   ```

No Termux, use `npm install --no-bin-links` no lugar do comando acima.

3. Copie `.env.example` para `.env`.
4. Preencha `ADMIN_PASSWORD` com uma senha forte.
5. Preencha `OWNER_WHATSAPP` com DDI + DDD + número, somente dígitos (ex.: `5511999999999`).
6. Preencha `OWNER_INSTAGRAM` com o usuário do Instagram, sem `@`.
7. Inicie:

   ```bash
   npm start
   ```

8. Abra `http://localhost:3000`.

## Publicar na internet (Render)

1. Envie esta pasta para um repositório Git (não envie `.env` nem `node_modules`).
2. No Render, crie um **Web Service** conectado ao repositório.
3. O `render.yaml` já informa build, start, health check e disco persistente (plano Starter). Se não importar o Blueprint, use `npm install` e `npm start`, e configure armazenamento persistente para `lib/secret`.
4. Em **Environment**, configure `ADMIN_PASSWORD`, `OWNER_WHATSAPP` e `OWNER_INSTAGRAM`.
5. Publique. O Render fornece uma URL pública HTTPS; use essa URL para acessar a plataforma.

O projeto fica preparado para hospedagem, mas a publicação real exige sua conta e a configuração do serviço de hospedagem. O endereço público só existe depois do deploy.

## Endereços

- `/` — página pública SIXVOID.
- `/docs.html` — documentação existente da base.
- `/solicitar-key.html` — solicitar chave ou recarga pelo WhatsApp.
- `/admin.html` — painel administrativo protegido.
- `/api/health` — verificação de disponibilidade.

## Segurança e dados

- Não coloque a senha administrativa no HTML, no JavaScript ou em URLs.
- A senha fica na variável `ADMIN_PASSWORD` do ambiente do servidor.
- As sessões administrativas usam cookie HttpOnly e expiram após 8 horas; reiniciar o servidor encerra as sessões existentes.
- Os dados existentes em `lib/secret/keys.json` e `usuarios.json` são preservados. Faça backup desses arquivos antes de publicar.
- A hospedagem precisa manter o armazenamento desses arquivos persistente. O Blueprint do Render configura um disco persistente; se escolher outro plano/provedor, monte um volume persistente em `lib/secret` ou migre os JSONs para banco de dados antes de usar em produção.
- O saldo é descontado em 2 unidades por chamada validada, conforme o comportamento original da base. O contador de estatísticas registra uma chamada por execução de `listkeys()`.
- A base original contém endpoints e dependências antigos; nem todos os serviços externos de scraping têm garantia de funcionamento permanente.

### Bloqueio de API Key

No painel, o botão **BLOQUEAR** suspende a chave imediatamente em todos os endpoints que validam `apikey`. **DESBLOQUEAR** restaura o acesso, desde que ainda exista saldo.
