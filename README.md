# IPVault

O IPVault é uma extensão para o Visual Studio projetada para proteger a Propriedade Intelectual (IP) do seu código fonte ao interagir com assistentes de IA. A extensão garante que nomes proprietários, como classes, funções e variáveis, não sejam enviados em texto claro para servidores externos.

## Como Funciona

A extensão atua como uma camada de segurança local. O fluxo de uso é composto por duas etapas principais:

1. **Geração do Mapa de Proteção (Generate IP Vault):**
   Ao acionar este comando, a extensão escaneia os arquivos do seu projeto e símbolos de compilação (arquivos PDB) para identificar termos proprietários. Ela cria um dicionário local que relaciona esses termos sensíveis a identificadores genéricos (exemplo: `Class_1`, `Var_2`, `Func_3`). Este processo ocorre inteiramente na sua máquina.

2. **Execução Protegida (Get MCP Server Config):**
   A extensão fornece a configuração de um Servidor MCP (Model Context Protocol). Este servidor utiliza o mapa gerado para interceptar e substituir automaticamente todos os termos protegidos no seu prompt antes do envio para a IA, e traduz de volta nas respostas. Você pode usar este servidor com seu agente preferido (como Claude Desktop, Roo Code, Cline).

## Cuidados de Segurança e Privacidade

Para garantir a proteção dos dados, os seguintes cuidados foram implementados:

* **Mascaramento Automático:** Nomes de arquivos, variáveis, propriedades e classes específicos do seu projeto são ofuscados.
* **Processamento Local:** A geração do dicionário e a substituição dos termos ocorrem estritamente na máquina do usuário através do Servidor MCP.
* **Isolamento de Ambiente:** A extensão possui seu próprio servidor MCP embutido. Isso garante que a versão com o filtro de segurança esteja sempre em uso.
* **Integração Flexível:** Por usar o padrão MCP via Stdio, nenhuma porta de rede é exposta e a integração com agentes modernos é transparente e segura.
* **Filtros e Exceções:** A ferramenta possui filtros internos para não ofuscar palavras-chave da linguagem (C/C++) ou bibliotecas de terceiros públicas (como `std`, `boost`, etc), garantindo que a IA ainda entenda o contexto da linguagem sem comprometer o código proprietário.

## Como Utilizar

1. Abra a sua *Solution* no Visual Studio.
2. Acesse as opções da extensão e execute **Generate IP Vault**.
3. Aguarde a mensagem de confirmação de que o mapa foi gerado.
4. Execute **Get MCP Server Config** para copiar a configuração do Servidor MCP e cole-a no seu agente favorito.