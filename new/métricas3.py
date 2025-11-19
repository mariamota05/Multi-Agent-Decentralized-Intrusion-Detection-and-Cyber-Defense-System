import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def load_and_clean_data(filename):
    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        print(f"Erro: O ficheiro '{filename}' não foi encontrado.")
        return None

    # --- Limpeza de Dados ---
    # Converter "3.082s" -> 3.082
    df['Response_Time'] = df['Metric3_Response_Time'].str.extract(r'(\d+\.\d+)').astype(float)
    # Converter "22.0%" -> 22.0
    df['Peak_CPU'] = df['Metric6_Victim_Peak_CPU'].str.replace('%', '').astype(float)
    # Converter "5 Pings OK" -> 5
    df['Pings_OK'] = df['Metric4_Service_Availability'].str.extract(r'(\d+)').astype(int)
    # Converter "6 msgs..." -> 6
    df['Leakage'] = df['Raw_Leakage_Count']

    # Converter Crash para cor/categoria
    df['Status'] = df['Metric7_Victim_Crashed'].apply(lambda x: 'Crash' if x == 'YES' else 'Alive')

    return df


def plot_alternative_graphs(df):
    sns.set_theme(style="whitegrid")

    # Obter as intensidades únicas para usar nos eixos X
    unique_intensities = sorted(df['Scenario_Intensity'].unique())

    # --- GRÁFICO 1: A Falésia de Performance (Dual Axis) ---
    # Este gráfico é ótimo para mostrar o colapso do sistema.
    fig, ax1 = plt.subplots(figsize=(12, 6))

    # Agrupar dados por intensidade (média) para ter linhas limpas
    df_grouped = df.groupby('Scenario_Intensity').agg({'Peak_CPU': 'mean', 'Pings_OK': 'mean'}).reset_index()

    # Eixo Y da Esquerda (CPU)
    sns.lineplot(data=df_grouped, x='Scenario_Intensity', y='Peak_CPU', ax=ax1, color='crimson', marker='o',
                 linewidth=3, label='Stress do CPU (%)')
    ax1.set_ylabel('Carga de CPU (%)', color='crimson', fontsize=12)
    ax1.tick_params(axis='y', labelcolor='crimson')
    ax1.set_ylim(0, 110)
    ax1.axhline(100, color='black', linestyle='--', alpha=0.3, label='Limite Físico')

    # --- CORREÇÃO AQUI: Forçar ticks do eixo X ---
    ax1.set_xticks(unique_intensities)
    # ---------------------------------------------

    # Eixo Y da Direita (Serviço)
    ax2 = ax1.twinx()
    # Usamos fill_between para criar uma "área" de serviço
    ax2.fill_between(df_grouped['Scenario_Intensity'], df_grouped['Pings_OK'], color='navy', alpha=0.2,
                     label='Disponibilidade de Serviço')
    sns.lineplot(data=df_grouped, x='Scenario_Intensity', y='Pings_OK', ax=ax2, color='navy', marker='s',
                 linestyle='--')
    ax2.set_ylabel('Pings Respondidos (Máx 5)', color='navy', fontsize=12)
    ax2.tick_params(axis='y', labelcolor='navy')
    ax2.set_ylim(0, 6)

    plt.title('A Falésia de Performance: Stress vs. Disponibilidade', fontsize=16, weight='bold')
    ax1.set_xlabel('Intensidade do Ataque DDoS', fontsize=12)

    # Legenda combinada manual
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='center left')

    plt.tight_layout()
    plt.savefig('grafico_falesia_performance.png', dpi=300)
    print("Gerado: grafico_falesia_performance.png")
    plt.show()

    # --- GRÁFICO 2: O Ponto de Rutura (Scatter com Status) ---
    # Mostra onde o sistema sobrevive vs onde morre.
    plt.figure(figsize=(10, 6))

    sns.scatterplot(
        data=df,
        x='Scenario_Intensity',
        y='Peak_CPU',
        hue='Status',
        style='Status',
        palette={'Crash': 'red', 'Alive': 'green'},
        s=150,
        alpha=0.8,
        edgecolor='black'
    )

    # Adicionar uma linha de tendência logística ou simples
    sns.regplot(data=df, x='Scenario_Intensity', y='Peak_CPU', scatter=False, color='gray',
                line_kws={'linestyle': '--'})

    plt.title('Ponto de Rutura: Sobrevivência por Intensidade', fontsize=16, weight='bold')
    plt.xlabel('Intensidade do Ataque', fontsize=12)
    plt.ylabel('Pico de CPU Atingido (%)', fontsize=12)
    plt.axhline(100, color='red', linestyle=':', label='Crash')
    plt.legend(title='Estado do Nó')

    # Aplicar também aqui para consistência
    plt.xticks(unique_intensities)

    plt.tight_layout()
    plt.savefig('grafico_ponto_rutura.png', dpi=300)
    print("Gerado: grafico_ponto_rutura.png")
    plt.show()

    # --- GRÁFICO 3: Custo da Latência (Leakage vs Response Time) ---
    # Tenta mostrar se demorar mais tempo resulta em mais fuga.
    plt.figure(figsize=(10, 6))

    scatter = sns.scatterplot(
        data=df,
        x='Response_Time',
        y='Leakage',
        hue='Scenario_Intensity',
        palette='viridis',
        size='Scenario_Intensity',
        sizes=(50, 200),
        alpha=0.8
    )

    plt.title('O Custo da Latência: Tempo de Resposta vs. Fuga', fontsize=16, weight='bold')
    plt.xlabel('Tempo de Resposta da Defesa (segundos)', fontsize=12)
    plt.ylabel('Mensagens Não Bloqueadas (Leakage)', fontsize=12)
    plt.legend(title='Intensidade', bbox_to_anchor=(1.05, 1), loc='upper left')

    plt.tight_layout()
    plt.savefig('grafico_custo_latencia.png', dpi=300)
    print("Gerado: grafico_custo_latencia.png")
    plt.show()


# Executar
if __name__ == "__main__":
    df = load_and_clean_data('../simulation_metrics_cpu.csv')
    if df is not None:
        plot_alternative_graphs(df)