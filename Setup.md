# IPVault Setup

## O que estava errado

O problema não era o código do IPVault. O VSIX estava sendo gerado corretamente, mas a instalação estava ficando presa em cache/instância do Visual Studio e o VS não estava reindexando a extensão no ambiente que você realmente usa.

O que resolveu:

1. Rebuild limpo do VSIX.
2. Instalação explícita no Visual Studio Professional 2026 correto.
3. Limpeza do cache do Visual Studio.
4. Reexecução de `devenv /setup` e `devenv /updateconfiguration`.
5. Instalação com elevação quando o Visual Studio está sendo usado como administrador.

## Diferença entre instalar para você e para outra pessoa

O VSIX é instalado por usuário e por instância do Visual Studio.

- Se o VS está aberto **normal**, a extensão precisa aparecer no perfil normal do usuário.
- Se o VS está aberto **como administrador**, ele pode usar cache/configuração diferente e a extensão precisa ser instalada e reconfigurada nesse contexto também.
- Se a extensão foi instalada em outra instância, ela pode existir em disco e mesmo assim não aparecer em **Tools** ou em **Manage Extensions** na instância errada.

## Instalar pelo VSIX

### Pré-requisitos

- Visual Studio Professional 2026 instalado.
- Feche todas as janelas do Visual Studio antes de instalar.
- Se você usa o VS como administrador, abra a instalação também como administrador.

### Passos

1. Localize o arquivo `.vsix` gerado em:

   `IPVault\bin\Debug\net472\IPVault.vsix`

2. Dê duplo clique no arquivo `.vsix`.
3. Se o Visual Studio estiver aberto, feche-o antes de continuar.
4. Confirme a instalação no instalador.
5. Abra o Visual Studio de novo.
6. Vá em **Tools** e procure **Generate Zero-Trust Vault**.
7. Se não aparecer, abra **Manage Extensions** e confira se `IPVault` está instalado.

### Se o VS estiver em modo administrador

Abra um **Prompt de Comando** ou **PowerShell** como administrador e rode:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\devenv.exe" /setup /nosplash
& "C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\devenv.exe" /updateconfiguration /nosplash
```

Depois abra o Visual Studio como administrador novamente.

## Instalar compilando o repositório

### Pré-requisitos

- .NET SDK compatível com o projeto.
- Visual Studio Professional 2026 com suporte a extensões VSSDK.
- Permissão para instalar extensões no Visual Studio.

### Passos

1. Clone o repositório.
2. Abra a solução `IPVault.slnx` ou o projeto `IPVault\IPVault.csproj`.
3. Compile em Debug:

```powershell
dotnet build .\IPVault.slnx -c Debug
```

4. O VSIX sai em:

```powershell
IPVault\bin\Debug\net472\IPVault.vsix
```

5. Instale esse `.vsix` no Visual Studio.
6. Feche e abra o Visual Studio novamente.

### Se você usa o VS como administrador

Depois de instalar, rode também:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\devenv.exe" /setup /nosplash
& "C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\devenv.exe" /updateconfiguration /nosplash
```

## Como validar

1. Abra uma solution C++.
2. Vá em **Tools > Generate Zero-Trust Vault**.
3. Verifique se o arquivo abaixo foi atualizado:

```powershell
$env:TEMP\ip_vault_map.json
```

4. Se não gerar, veja o log:

```powershell
$env:TEMP\ip_vault_ext_log.txt
```

## Troubleshooting rápido

- **Não aparece em Tools**: feche o VS, rode `devenv /setup` e `devenv /updateconfiguration`, e abra novamente.
- **Não aparece em Manage Extensions**: você provavelmente está olhando a instância errada do VS ou o cache não foi reindexado.
- **VS como administrador**: sempre valide a instalação nesse mesmo modo.
- **JSON não nasce**: confira o log em `%TEMP%\ip_vault_ext_log.txt`.
