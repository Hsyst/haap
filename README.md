# HAAP
## H
syst
### A
uth
### A
uthorization
### P
lugin

# Introdução
Olá! Bem vindo(a) ao HAAP, antes de começar, apesar de receber o nome de Hsyst Auth, ele é um sistema de login totalmente refeito do zero, o que junto com isso, traz novos recursos e formas de funcionamento, e portanto, trate isso como uma atualização do Hsyst Auth, mas sem ligação nenhuma com a versão anterior.

# Tutorial de Uso
Quer utilizar, mas não quer ler uma documentação técnica inteira? [Clique Aqui!](#)

# Documentação Técnica
## Introdução
A documentação técnica é um documento que descreve a função do código em linguagem técnica, e portanto, esta parte é dedicada a pessoas que querem entender como o sistema funciona de forma técnica, então, caso você não entenda de tecnologia, eu recomendo que se mantenha apenas no [Tutorial de Uso](#) que eu tenho certeza que vai te dar o material o suficiente para executar e configurar o sistema, e com uma linguagem amigável.

## Funcionalidades
Este código, vem com um sistema de login *interno* e *externo*, apesar de lidarem com os mesmos dados, eles tratam e são usados para finalidades diferentes.

- Login Interno
O *Login Interno* é o login utilizado para acessar as páginas privadas do sistema, ou seja, dashboard em geral e páginas privadas (Pasta: public/ (Obs:. Pode parecer estranho lidar com o fato de que a pasta public é as páginas privadas do serviço, mas é pra tentar deixar mais amigável pra desenvolvedores que este é o local onde uma homepage deve ser colocada por exemplo)).

- Login Externo
Diferente do *Login Interno*, o *Login Externo* funciona também com os usuários cadastrados localmente, mas ele na verdade, é basicamente um *OAuth* proprietário para este software, com ele, você pode criar *Links Externos* que vão ser usados para realizar o login em uma aplicação externa usando a base de dados do seu HAAP Local.

## Funcionamento do *Login Externo*
Esta parte precisa de uma parte dedicada, já que é uma função relativamente complexa, que pode ser usada por muitas pessoas, e certamente, apenas com a leitura do código pode ser díficil entender, por isso, este tópico foi criado.

### Parte do HAAP
Ao entrar em sua conta no seu HAAP, ele terá uma sessão denominada "Links Externos". Esta sessão é aonde você pode criar o Link Externo, que é nada mais nada menos que um link que ao ser acessado, pede a autorização do/da usuário(a) para um serviço externo adquirir seus dados.

### Ao clicar no Link:
Ao clicar no link externo, ele pedirá autorização para o uso dos dados, e ao ser autorizado, a pessoa é redirecionada para o...

### Servidor Externo
No servidor externo, ele receberá um callback code, que o backend do serviço externo deverá utilizar para adquirir os dados do/da usuário(a). E quando o servidor externo...

### Adquirir o callback code
Ele poderá adquirir os dados do usuário com o callback code (validade de 30s) que dará acesso ao token externo, que é nada menos que um token que pode ser usado até 3 vezes para buscar os dados do/da usuário(a) e pegar esses dados para usar como quiser, como por exemplo, pra criar um jwt assinado pelo seu servidor externo com os dados.

## Exemplo de funcionamento
Junto a este repositório, tem uma pasta teste, que dentro dela tem o arquivo [index.py](https://github.com/Hsyst/haap/blob/main/teste/index.py), e este código é um exemplo de Servidor Externo, então, eu recomendo ler este código para entender como implementar no seu serviço o login com HAAP.

## Funcionamento de páginas
Caso você queira utilizar o HAAP como um web server, isso é possivel, e basicamente, nós temos duas pastas que representam o "/" da web, que no caso, é o:

- service/
Diretório de arquivos do serviço, nada mais que a pasta onde ficam as páginas que não precisam de autenticação.

- public/
Diretório de arquivos "privados" (apesar da pasta ser public, é por conta de que isso facilita o entendimento que que é nesta página que sua homepage protegida com o sistema de Login Interno deverá ser colocada) é aonde ficam os arquivos de páginas que dependem de login para entrar.

- Mas afinal, o que acontece se eu colocar um arquivo com o mesmo nome nas duas pastas?
Ele vai dar conflito, e vai expor isso em seu console, e como resposta para o cliente. Ou seja, como as duas pastas representam o mesmo diretório na web, ao ter dois arquivos com o mesmo nome nas duas pastas, ele não tem como saber qual dos diretórios ele deve dar prioridade, e portanto, vai exibir o erro.

# Créditos
Sistema criado por mim [Thais (op3n/op3ny)](https://github.com/op3n)

# Licença
Este projeto está sob as condições e termos da licença [Apache License 2.0](https://github.com/Hsyst/haap/blob/main/LICENSE)
