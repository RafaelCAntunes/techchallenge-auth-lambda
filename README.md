# techchallenge-auth-lambda

foram criadas 2 rotas:

- Autenticação via cpf (que gera um JTW token)
- Validação do JWT token

No caso da criação de um pedido sem identificação, bastaria gerar um JWT válido genérico para esse tipo de solicitação.