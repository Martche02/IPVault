# Guia de Uso do Servidor MCP (IP Vault)

Este documento descreve as diretrizes e aprendizados para agentes de IA interagirem com o ambiente protegido pelo servidor MCP (IP Vault). O ambiente contém código-fonte (predominantemente C/C++) que é confidencial.

## 1. O que é o IP Vault MCP?
O IP Vault é um servidor MCP (Model Context Protocol) projetado para proteger a propriedade intelectual (IP) do código. Ele atua como um intermediário entre o agente e os arquivos reais do projeto no disco, permitindo assistência sem expor os nomes originais e lógicas de negócios restritas.

## 2. Mascaramento de Dados (Data Masking)
A característica mais importante deste ambiente é que **nomes de arquivos, pastas, classes, variáveis e funções são frequentemente mascarados**.
- **Como aparece:** Você verá identificadores gerados, como `File_198`, `Class_6972`, `Func_2830_4494`, `Var_912`, `Enum_3521`, etc.
- **Como trabalhar:** Você pode e deve trabalhar **normalmente** com esses nomes mascarados. Se você precisar passar um caminho de arquivo para uma ferramenta MCP ou para o compilador (MSBuild), use a string mascarada exatamente como ela foi apresentada (ex: `File_295\File_302.cpp`). O servidor MCP se encarrega de traduzir o nome mascarado de volta para o nome real no sistema de arquivos local.

## 3. Ferramentas MCP Disponíveis
Você deve utilizar as ferramentas específicas com o prefixo `mcp_ipvault_mcp_` para interagir com este ambiente:
- **`mcp_ipvault_mcp_exec_command`**: Executa comandos no ambiente protegido (ex: chamadas ao `msbuild`, `dir`, `powershell`). O output (stdout/stderr) é automaticamente mascarado e filtrado antes de chegar a você.
- **`mcp_ipvault_mcp_read_file`**: Lê o conteúdo de um arquivo mascarado. **Nota:** Muitas vezes, usar caminhos absolutos pode falhar dependendo de como a raiz do projeto foi mapeada. Prefira usar caminhos relativos ao usar esta ferramenta.
- **`mcp_ipvault_mcp_write_file`**: Escreve ou sobrescreve arquivos no ambiente. Você envia o conteúdo com nomes mascarados (ou na sua lógica inferida) e o servidor cuida do resto.
- **`mcp_ipvault_mcp_show_to_user`**: Abre o arquivo original (sem máscara) no Notepad para que o usuário humano possa ler o código real. Isso é extremamente útil quando as máscaras tornam a lógica indecifrável para o agente, ou quando ocorrem erros de compilação confusos que o usuário pode identificar facilmente olhando o original.

## 4. Compilação (MSBuild) e Visual Studio
O projeto principal protegido geralmente é uma solução Visual Studio (C++).
- Para compilar, você precisará invocar o MSBuild via `mcp_ipvault_mcp_exec_command`.
- **Dica Crítica de Ambiente:** O MSBuild requer que as variáveis de ambiente do Visual Studio estejam presentes. Você deve encadear a chamada do `vcvars64.bat` com o comando MSBuild na mesma execução, ou criar um arquivo `.bat` temporário (ex: `vault_build.bat`) que faça isso, e executá-lo.
- **Dica Crítica de Path (Erros MSB4019):** Sempre passe o parâmetro `/p:SolutionDir=%CD%\` (ou o caminho raiz da solução) para o MSBuild. Se você não fizer isso, imports relativos de arquivos `.props` ou `.targets` podem falhar, gerando erros como o `MSB4019`.
- **Exemplo de comando MSBuild robusto no vault:**
  `cmd /c "call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" x64 && msbuild ProjectDir\Project.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir=%CD%\\"`

## 5. Cuidados e Troubleshooting
- **Manipulação de Strings via Terminal:** Evite tentar editar arquivos protegidos via comandos PowerShell (como `-replace`) passados ao `mcp_exec_command`. O mascaramento interfere fortemente com expressões regulares e strings literais (ex: substituir `severity()` por `log_severity()` via shell pode falhar e corromper o arquivo com caracteres inválidos UTF-8/65001, como ocorreu com o erro `C4828`). É muito mais seguro fornecer a instrução exata ao usuário humano ou tentar sobrescrever o arquivo inteiro via `mcp_write_file`.
- **Caminhos de Drive:** O drive `C:` muitas vezes aparece mascarado (ex: `Var_912:\`). No entanto, chamadas para binários e ferramentas do sistema que residem fora do vault (como o próprio `vcvars64.bat` e `msbuild`) ainda exigem caminhos tradicionais absolutos como `C:\Program Files\...`.
- **Tradução LNK / MSVC:** Os erros do compilador (CXXXX) e linker (LNKXXXX) também vêm com seus parâmetros mascarados. Trate os nomes mascarados logicamente. Exemplo: Se o log disser que `Class_3470` não é membro de `Func_2830`, você sabe estruturalmente que a classe original não tem o método chamado; guie a correção com base no comportamento do C++ padrão e no contexto do problema, e deixe o servidor MCP traduzir as edições ou peça a ajuda visual do usuário.
