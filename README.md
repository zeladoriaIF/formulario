# Pesquisa IFUSP de Ambiente de Trabalho

Aplicação local/deployável com:

- autenticação de servidores por número USP e três primeiros dígitos do CPF;
- autenticação administrativa;
- banco de autenticação separado do banco de respostas;
- controle de uma resposta por pessoa;
- painel ADM sem número USP;
- exportação anônima em CSV e JSON pelo navegador;
- rate limit de tentativas de login;
- respostas salvas sem IP, user-agent ou horário exato.
- modo de apresentação `teste` / `teste`, cujas respostas nunca são gravadas.

## Base importada

A planilha fornecida em 12/06/2026 contém 233 registros válidos e únicos. A aplicação usa `233` como total elegível.

O arquivo `.xls` original não fica na pasta pública. Durante a importação:

- o número USP vira um HMAC para busca;
- os três primeiros dígitos do CPF viram um hash `scrypt` com salt individual;
- o CPF completo não é gravado;
- o número USP em texto não é gravado.

## Executar

Requer Node.js 24 ou superior.

```powershell
node server.mjs
```

Abra `http://127.0.0.1:8787`.

O login e a senha administrativos são definidos na importação. Antes da publicação, use uma senha longa e exclusiva.

Para apresentações:

- login: `teste`
- senha: `teste`

Esse acesso permite percorrer e enviar o formulário, mas não altera a contagem, os gráficos, as exportações ou o banco de respostas.

## Reimportar ou atualizar a base

Feche o servidor e execute:

```powershell
.\importar-planilha.ps1 `
  -Planilha "C:\caminho\Banco de dados formulário.xls" `
  -NodeExe "C:\caminho\node.exe" `
  -AdminLogin "ADM" `
  -AdminPassword "uma-senha-forte"
```

A reimportação mantém a marcação de quem já respondeu, desde que o número USP continue na base.

## Publicação

Para domínio institucional:

1. instalar Node.js 24 no servidor;
2. manter `data/` fora de qualquer diretório público;
3. executar atrás de proxy HTTPS, como Nginx ou Apache;
4. definir `NODE_ENV=production` para cookie `Secure`;
5. restringir leitura de `data/app-secret.key`, `data/auth.db` e `data/responses.db` ao usuário do serviço;
6. manter backup criptografado;
7. usar 2FA ou autenticação institucional para o ADM quando possível.

## Limitação de segurança conhecida

Uma senha de três dígitos tem apenas 1.000 combinações. A aplicação aplica limitação de tentativas, mas a opção mais segura para produção é autenticação USP institucional ou código de acesso aleatório individual.
