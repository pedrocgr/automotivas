# Etapa 5 - Deteccao de Intrusoes

Este guia e a receita para refazer os testes da Etapa 5 com logs novos.

Importante: rode todos os comandos a partir desta pasta:

```bash
cd ~/code/automotivas/yes-carla-can
```

Se voce rodar da pasta `~/code/automotivas`, os comandos com `data/...`,
`logs/...` e `intrusion_detection_module.py` vao falhar.

## Objetivo da Etapa 5

A especificacao pede:

- executar o IDS `id_time` junto com um ataque;
- medir intrusoes detectadas por ID CAN durante o ataque;
- medir falsos positivos sem ataque;
- propor uma melhoria para o algoritmo.

Vamos usar o ataque `hand_brake`, porque ele e facil de ver no CARLA e altera
claramente o ID `0x604`.

## O que vamos gerar

Depois dos testes, estes arquivos devem existir:

```text
logs/etapa5_normal.log
logs/etapa5_handbrake_attack.log
data/etapa5_detection/id_time_detection_results.json
data/etapa5_detection/id_time_detection_results.csv
data/etapa5_detection/id_time_detection_counts.png
data/etapa5_detection/id_time_detection_counts_original.png
data/etapa5_detection/id_time_detection_counts_improved.png
```

O grafico pode ter barra normal igual a zero. Isso nao e erro. Para a Etapa 5,
normal igual a zero significa que o IDS nao gerou falso positivo.

## 1. Subir o ambiente

Terminal 1:

```bash
cd ~/code/automotivas/yes-carla-can
./1_up_environment.sh --dbc data/carla.dbc
```

Espere aparecer `Environment is up!` e confirme que o carro esta controlavel.

## 2. Teste normal, sem ataque

Este teste mede falsos positivos. Nao rode nenhum ataque durante esta captura.

Terminal 2:

```bash
cd ~/code/automotivas/yes-carla-can
candump -L vcan0 | tee logs/etapa5_normal.log
```

No CARLA, dirija normalmente por 60 a 90 segundos:

- acelere;
- freie;
- vire um pouco;
- deixe o carro parado alguns segundos tambem.

Depois pare a captura com `Ctrl+C`.

Confira se o arquivo foi criado:

```bash
ls -lh logs/etapa5_normal.log
```

Se esse arquivo nao existir, nao rode o analyzer ainda.

## 3. Teste com ataque de handbrake

Este teste mede se o IDS detecta o ataque no ID `0x604`.

Terminal 2: iniciar a captura do trafego com ataque.

```bash
cd ~/code/automotivas/yes-carla-can
candump -L vcan0 | tee logs/etapa5_handbrake_attack.log
```

Terminal 3: iniciar o IDS ao vivo, para gravar video/print se quiser.

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 intrusion_detection_module.py \
  --detector id_time
```

Terminal 4: iniciar o ataque.

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py \
  --feature hand_brake \
  --period 0.05
```

Durante o teste:

- tente acelerar o carro;
- observe se o freio de mao fica forcado;
- observe se o IDS aumenta a contagem de intrusoes no ID `604` ou `0x604`;
- grave video se quiser usar como evidencia visual.

Depois de 60 a 90 segundos, pare nesta ordem:

1. `Ctrl+C` no ataque;
2. `Ctrl+C` no IDS;
3. `Ctrl+C` no `candump`.

Confira se o arquivo foi criado:

```bash
ls -lh logs/etapa5_handbrake_attack.log
```

## 4. Gerar resultados e grafico

So rode este passo depois de confirmar que os dois logs existem.

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python data/id_time_detection_analyzer.py \
  --normal logs/etapa5_normal.log \
  --attack logs/etapa5_handbrake_attack.log \
  --output-dir data/etapa5_detection \
  --plots \
  --compare-versions
```

Confira os resultados:

```bash
cat data/etapa5_detection/id_time_detection_results.csv
```

Abra/veja o grafico:

```bash
ls -lh data/etapa5_detection/id_time_detection_counts.png
ls -lh data/etapa5_detection/id_time_detection_counts_original.png
ls -lh data/etapa5_detection/id_time_detection_counts_improved.png
```

Resultado esperado:

- cenario `normal`: `0` ou poucos alertas;
- cenario `attack`: muitos alertas;
- ID principal detectado: `0x604`.

Se o normal der `0`, perfeito: taxa de falso positivo `0%`.

## 4.1. Comparacao original vs melhorado

O analyzer tambem consegue gerar uma comparacao entre duas versoes do detector:

- `original`: comportamento inicial do `id_time`, mantido apenas para comparacao
  offline;
- `improved`: comportamento corrigido, usado atualmente pelo IDS ao vivo.

A versao original e interessante para o relatorio porque mostra falsos positivos no
cenario normal. Nos logs novos, ela marcou todas as mensagens normais como intrusoes
porque comparava IDs no formato `0x604` contra estatisticas no formato `604`.

Arquivos da comparacao:

```text
data/etapa5_detection/id_time_detection_original_results.csv
data/etapa5_detection/id_time_detection_improved_results.csv
data/etapa5_detection/id_time_detection_versions.json
data/etapa5_detection/id_time_detection_counts_original.png
data/etapa5_detection/id_time_detection_counts_improved.png
```

Para ver os numeros:

```bash
cat data/etapa5_detection/id_time_detection_original_results.csv
cat data/etapa5_detection/id_time_detection_improved_results.csv
```

Nos logs capturados em laboratorio, os resultados foram:

| Versao | Cenario normal | Cenario com ataque |
|---|---:|---:|
| original | 2818 alertas | 3026 alertas |
| improved | 0 alertas | 527 alertas no ID `0x604` |

Interpretacao para o relatorio:

```text
A versao original do detector gerou falsos positivos no cenario normal porque havia
incompatibilidade entre o formato dos IDs CAN recebidos e o formato dos IDs no
baseline. A melhoria normalizou os IDs e passou a calcular anomalias sobre intervalos
entre mensagens, reduzindo os falsos positivos normais para 0 e mantendo deteccao do
ataque hand_brake no ID 0x604.
```

## 5. Atualizar pasta do Overleaf

Depois de gerar o grafico novo, copie ele para a pasta do Overleaf:

```bash
cd ~/code/automotivas
cp yes-carla-can/data/etapa5_detection/id_time_detection_counts.png \
  overleaf_etapa5/figures/id_time_detection_counts.png
cp yes-carla-can/data/etapa5_detection/id_time_detection_counts_original.png \
  overleaf_etapa5/figures/id_time_detection_counts_original.png
cp yes-carla-can/data/etapa5_detection/id_time_detection_counts_improved.png \
  overleaf_etapa5/figures/id_time_detection_counts_improved.png
```

Se quiser gerar o zip de novo:

```bash
cd ~/code/automotivas
zip -r overleaf_etapa5.zip overleaf_etapa5/main.tex overleaf_etapa5/figures
```

Depois, no Overleaf, envie a pasta/zip `overleaf_etapa5`.

## 6. Usar logs antigos se estiver sem tempo

Se voce nao conseguir capturar logs novos, pode gerar resultados com os logs que ja
existem no repositorio:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python data/id_time_detection_analyzer.py \
  --normal logs/normal.log \
  --attack logs/spoofing_handbrake.log \
  --output-dir data/etapa5_detection \
  --plots
```

Mas para a entrega, o ideal e usar os logs novos `etapa5_normal.log` e
`etapa5_handbrake_attack.log`, porque eles correspondem diretamente ao teste que voce
rodou no laboratorio.

## 7. Erros comuns

### `can't open file ... intrusion_detection_module.py`

Voce provavelmente esta em `~/code/automotivas`.

Entre na pasta certa:

```bash
cd ~/code/automotivas/yes-carla-can
```

Depois rode:

```bash
conda run --no-capture-output -n n4s_env python3 intrusion_detection_module.py \
  --detector id_time
```

### `FileNotFoundError: logs/etapa5_normal.log`

O arquivo ainda nao foi capturado.

Crie primeiro com:

```bash
candump -L vcan0 | tee logs/etapa5_normal.log
```

Depois rode o analyzer.

### `candump: command not found`

Instale `can-utils`:

```bash
sudo apt install can-utils
```

### `vcan0: No such device`

O ambiente ainda nao esta de pe, ou o `vcan0` nao foi criado.

Rode:

```bash
./1_up_environment.sh --dbc data/carla.dbc
```

## 8. O que escrever no relatorio

Use os numeros do arquivo:

```bash
cat data/etapa5_detection/id_time_detection_results.csv
```

Modelo de interpretacao:

```text
No cenario normal, o IDS detectou X intrusoes em Y mensagens, resultando em taxa de
falsos positivos de X/Y.

Durante o ataque hand_brake, o IDS detectou Z intrusoes no ID 0x604. Esse resultado
e coerente com o ataque, pois o spoofing injeta mensagens do freio de mao em periodo
menor que o periodo normal observado para esse ID.
```

Proposta de melhoria:

- combinar deteccao temporal com validacao de payload pelo DBC;
- registrar alertas em CSV/JSON durante a execucao ao vivo;
- usar janela de aquecimento para ignorar instabilidade inicial;
- classificar severidade por persistencia do alerta;
- detectar tambem transicoes de estado impossiveis ou improvaveis.
