# Guia de Uso do Servidor MCP (IP Vault - Versão Python)

Este documento descreve as diretrizes e aprendizados para agentes de IA interagirem com o ambiente protegido pelo servidor MCP (IP Vault) no VS Code. O ambiente contém código-fonte (predominantemente Python, SQL e scripts Batch) que é confidencial.

## 1. O que é o IP Vault MCP?
O IP Vault é um servidor MCP (Model Context Protocol) projetado para proteger a propriedade intelectual (IP) do código. Ele atua como um intermediário entre o agente e os arquivos reais do projeto no disco, permitindo assistência sem expor os nomes originais de classes, funções, variáveis e arquivos.

## 2. Mascaramento de Dados (Data Masking)
A característica mais importante deste ambiente é que **nomes de arquivos, pastas, classes, variáveis e funções proprietários são mascarados**.
- **Como aparece:** Você verá identificadores gerados, como `File_198`, `Class_6972`, `Func_2830`, `Var_912`, etc.
- **Bibliotecas Externas:** Nomes de pacotes externos públicos (como `pandas`, `numpy`, `sklearn`, `matplotlib`) e funções/palavras-chave nativas do Python não são mascarados, preservando o contexto da biblioteca usada.
- **Como trabalhar:** Você pode e deve trabalhar **normalmente** com esses nomes mascarados. Se você precisar passar um caminho de arquivo para uma ferramenta MCP ou para o terminal, use a string mascarada exatamente como ela foi apresentada (ex: `File_295\File_302.py`). O servidor MCP se encarrega de traduzir o nome mascarado de volta para o nome real no sistema de arquivos local.

## 3. Ferramentas MCP Disponíveis
Você deve utilizar as ferramentas específicas para interagir com este ambiente:
- **`mcp_read_file`**: Lê o conteúdo de um arquivo mascarado. Prefira usar caminhos relativos ao usar esta ferramenta.
- **`mcp_write_file`**: Escreve ou sobrescreve arquivos no ambiente. Você envia o conteúdo com nomes mascarados e o servidor cuida de traduzir de volta antes de salvar no disco.
- **`mcp_exec_command`**: Executa comandos no ambiente protegido (ex: chamadas ao `python`, `pytest`, `pip`). O output (stdout/stderr) é automaticamente mascarado e filtrado antes de chegar a você.
- **`mcp_show_to_user`**: Abre o arquivo original (sem máscara) no Notepad para que o usuário humano possa ler o código real. Útil se as máscaras tornarem a lógica indecifrável para o agente ou para depurar erros complexos.

## 4. Execução de Scripts e Testes (Python)
- Para rodar scripts ou testes, utilize `mcp_exec_command`.
- **Dica de Ambiente Virtual:** Se o projeto utilizar um virtualenv (ex: `.venv`), certifique-se de ativar ou usar o executável do python correto (ex: `.venv\Scripts\python.exe` no Windows) ao invés do python global.
- Exemplo de comando robusto para rodar testes:
  `cmd /c ".venv\Scripts\python.exe -m pytest"`

## 5. Cuidados e Troubleshooting
- **Manipulação de Strings via Terminal:** Evite tentar editar arquivos protegidos via comandos PowerShell (como `-replace`) ou scripts de shell passados ao `mcp_exec_command`. O mascaramento interfere fortemente com expressões regulares e strings literais. É muito mais seguro sobrescrever o arquivo via `mcp_write_file`.
- **Caminhos de Drive:** O drive `C:` pode aparecer mascarado (ex: `Var_912:\`). No entanto, chamadas para binários e ferramentas fora do vault ainda exigem caminhos tradicionais absolutos como `C:\Python312\...`.
- **f-strings no Python:** Ao lidar com f-strings, saiba que o servidor MCP protege expressões dentro das chaves `{}` mantendo a estrutura literal ao redor. Escreva f-strings com os termos mascarados normais dentro de `{}`.
