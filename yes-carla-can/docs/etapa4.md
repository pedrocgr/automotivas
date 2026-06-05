# Etapa 4 - Manipulacao de Mensagens e Analise de Impacto

Esta etapa pede experimentos de manipulacao de mensagens CAN e registro do impacto
visual no CARLA.

Pela especificacao, devem ser feitos:

- dois ataques de spoofing sobre funcoes veiculares distintas;
- um ataque fuzzy;
- registro do ID CAN alvo, periodo usado, captura visual e diferenca de comportamento
  com e sem ataque.

## Observacao sobre o DBC

O modulo `cyberattacks_module.py` usa IDs CAN hardcoded em
`attacks/reverse_engineering.py`. Esses IDs correspondem ao DBC padrao
`data/carla.dbc`.

Por isso, para Etapa 4, use o DBC padrao ao executar ataques como `reverse`, luzes,
portas e `fuzzy`:

```bash
cd ~/code/automotivas/yes-carla-can
./1_up_environment.sh --dbc data/carla.dbc
```

Com o DBC customizado da Etapa 2, o ataque `hand_brake` continua consistente porque
o ID `0x604` foi mantido. Ja o ataque `reverse` deve ser executado com o DBC padrao:
no DBC padrao, `REVERSE` usa o ID `0x603`; no DBC customizado, essa mensagem foi
movida para `0x714`.

## 1. Ataque de spoofing: hand_brake

Funcao atacada:

- feature: `hand_brake`
- ID CAN alvo: `0x604`
- payload: `01`
- periodo sugerido: `0.05 s`

Comando:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py \
  --feature hand_brake \
  --period 0.05
```

Impacto esperado:

- o freio de mao passa a ser continuamente forçado;
- o veiculo deixa de se mover ou apresenta grande dificuldade para sair do lugar;
- no trafego CAN, a contagem do ID `0x604` aumenta fortemente.

## 2. Ataque de spoofing: reverse

Funcao atacada:

- feature: `reverse`
- ID CAN alvo: `0x603`
- payload: `01`
- periodo sugerido: `0.05 s`

Observacao: o mapeamento original do ataque apontava para `0x607` com payload
`FF FF FF FF`, mas `0x607` e a mensagem `GEAR` no DBC padrao. O ataque foi corrigido
para enviar `0x603#01`, que corresponde ao campo `REVERSE`.

Comando:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py \
  --feature reverse \
  --period 0.05
```

Impacto esperado:

- o atacante injeta mensagens associadas ao estado de marcha re;
- o comportamento do veiculo pode ficar inconsistente com os comandos normais;
- no trafego CAN, a contagem do ID `0x603` aumenta durante o ataque corrigido.

## 3. Ataque fuzzy

Comando especificado na atividade:

```bash
cd ~/code/automotivas/yes-carla-can
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py \
  --feature fuzzy \
  --period 0.05
```

Observacao: na implementacao atual, o argumento `--period` nao controla o fuzzy. O
codigo escolhe funcoes aleatorias e envia mensagens em intervalos aleatorios entre
0,5 s e 1,0 s.

Durante o fuzzy, registre quais funcoes foram afetadas visualmente, por exemplo:

- freio de mao;
- marcha re;
- luzes;
- setas;
- portas.

Nos testes realizados, o fuzzy funcionou. Os efeitos mais faceis de perceber foram a
abertura das portas e o acionamento do freio de mao.

## 4. Evidencias a coletar

Para cada ataque:

- video ou trecho de video antes/durante o ataque;
- comando usado;
- ID CAN alvo;
- periodo configurado;
- descricao do comportamento observado no CARLA.

## 5. Artefatos ja existentes no repositorio

Ja existem logs e graficos para dois ataques de spoofing:

- `logs/normal.log`
- `logs/spoofing_handbrake.log`
- `logs/spoofing_reverse.log`
- `logs/analysis_outputs/05_comparacao_quantitativa_ids_atacados.csv`
- `logs/plots/03_contagem_id_604_normal_vs_handbrake.png`
- `logs/plots/04_contagem_id_607_normal_vs_reverse.png`
- `logs/plots/02_periodo_medio_id_604.png`

Resumo quantitativo desses logs:

| Comparacao | ID alvo | Normal | Ataque | Mensagens extras | Taxa normal | Taxa ataque |
|---|---:|---:|---:|---:|---:|---:|
| normal vs hand_brake | `0x604` | 342 | 2003 | 1661 | 4,82 msg/s | 22,78 msg/s |

## 6. Resultado final observado

- `hand_brake`: funcionou e impediu/dificultou o movimento do veiculo;
- `reverse`: passou a funcionar depois da correcao do ID/payload para `0x603#01`;
- `fuzzy`: funcionou, com efeitos mais perceptiveis em portas e freio de mao.
