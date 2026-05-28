# Etapa 3 - Captura e Analise do Trafego CAN

Este repositorio Git e `automotivas`. O projeto CARLA fica dentro da pasta
`yes-carla-can`, entao os comandos do simulador devem ser executados a partir de:

```bash
cd ~/code/automotivas/yes-carla-can
```

## 0. Preparar ambiente

Em um terminal novo, confirme que o conda esta disponivel:

```bash
conda --version
```

Se o comando ainda nao aparecer, carregue o conda instalado em `~/miniconda3`:

```bash
source ~/miniconda3/etc/profile.d/conda.sh
```

Crie/atualize o ambiente Python do projeto:

```bash
cd ~/code/automotivas/yes-carla-can
conda create -y -n n4s_env python=3.9
conda run -n n4s_env python -m pip install -r requirements.txt
```

Instale as ferramentas de CAN no sistema. Este comando pede sua senha:

```bash
sudo apt install -y can-utils
```

Se o CARLA ainda nao existir em `yes-carla-can/carla-0-9-15`, rode o instalador do
projeto. Ele tambem tenta instalar pacotes de sistema e baixa o CARLA:

```bash
cd ~/code/automotivas/yes-carla-can
./0_install_dependencies.sh
```

## 1. Subir o ambiente

Use o DBC customizado descrito no relatorio da Etapa 2:

```bash
cd ~/code/automotivas/yes-carla-can
./1_up_environment.sh --dbc data/our_dbcfile.dbc
```

Confirme no terminal do modulo de controle que a plataforma carregou:

```text
[CAN] DBC loaded: data/our_dbcfile.dbc
[CAN] Periodic messages scheduled: BRAKE(200ms) GEAR(200ms) HAND_BRAKE(200ms) MANUAL_TRANSMISSION(500ms) REVERSE(200ms) STEER(50ms) THROTTLE(50ms)
```

## 2. Capturar trafego normal

Abra outro terminal e rode:

```bash
cd ~/code/automotivas/yes-carla-can
mkdir -p data/etapa3_captures
cd data/etapa3_captures
candump -l vcan0
```

Deixe a captura rodar por um intervalo fixo, por exemplo 60 s. Depois interrompa com
`Ctrl+C` e renomeie o arquivo:

```bash
mv candump-*.log normal.log
```

## 3. Capturar trafego com spoofing

Inicie uma nova captura:

```bash
cd ~/code/automotivas/yes-carla-can/data/etapa3_captures
candump -l vcan0
```

Em outro terminal, execute um ataque de spoofing. Com o DBC customizado da Etapa 2,
`hand_brake` e um alvo consistente porque manteve o ID `0x604`:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py --feature hand_brake --period 0.01
```

Capture pelo mesmo intervalo usado no cenario normal, interrompa o `candump` e
renomeie o log:

```bash
mv candump-*.log spoofing_hand_brake.log
```

## 4. Gerar estatisticas e graficos

Volte para a pasta do projeto e rode:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 data/can_bus_data_analyzer.py \
  --normal data/etapa3_captures/normal.log \
  --attack data/etapa3_captures/spoofing_hand_brake.log \
  --output-dir data/etapa3_analysis \
  --plots
```

Saidas esperadas:

- `data/etapa3_analysis/normal_statistics.json`
- `data/etapa3_analysis/spoofing_statistics.json`
- `data/etapa3_analysis/normal_vs_spoofing_comparison.json`
- `data/etapa3_analysis/normal_statistics.csv`
- `data/etapa3_analysis/spoofing_statistics.csv`
- `data/etapa3_analysis/normal_vs_spoofing_comparison.csv`
- `data/etapa3_analysis/message_counts_by_id.png`
- `data/etapa3_analysis/mean_period_by_id.png`

## 5. Encerrar ambiente

Quando terminar:

```bash
cd ~/code/automotivas/yes-carla-can
./2_down_environment.sh
```

## 6. Pontos para o relatorio

Registre para cada cenario:

- tempo de captura;
- comando usado;
- contagem de mensagens por ID CAN;
- periodo medio e desvio padrao por ID CAN;
- diferenca quantitativa entre normal e spoofing.

No ataque `hand_brake`, espera-se aumento expressivo da contagem e da taxa de
mensagens no ID `0x604`, pois o atacante injeta frames adicionais no mesmo ID da
funcao de freio de mao.
