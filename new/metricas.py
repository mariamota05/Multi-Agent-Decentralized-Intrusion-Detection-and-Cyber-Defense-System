import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_and_clean_data(filename):
    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        print(f"Erro: O ficheiro '{filename}' não foi encontrado.")
        return None

    # --- Limpeza e Conversão ---
    # Extrair números das strings
    if 'Metric3_Response_Time' in df.columns:
        df['Response_Time'] = df['Metric3_Response_Time'].str.extract(r'(\d+\.\d+)').astype(float)
    if 'Metric6_Victim_Peak_CPU' in df.columns:
        df['Peak_CPU'] = df['Metric6_Victim_Peak_CPU'].str.replace('%', '').astype(float)

    # Garantir que a Intensidade é numérica e inteira
    if 'Scenario_Intensity' in df.columns:
        df['Scenario_Intensity'] = df['Scenario_Intensity'].astype(int)

    # Criar ID de Execução para o gráfico de barras individuais
    if 'Scenario_Intensity' in df.columns:
        df['Run_ID'] = df.groupby('Scenario_Intensity').cumcount() + 1

    return df


def plot_physical_impact(df):
    """Gera e mostra o gráfico de Impacto Físico (Pico de CPU)."""
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(10, 6))

    # Gráfico de barras individuais
    sns.barplot(
        x='Scenario_Intensity',
        y='Peak_CPU',
        hue='Run_ID',
        data=df,
        palette='viridis',
        edgecolor='black'
    )

    plt.title('Impacto Físico: Pico de CPU por Teste', fontsize=16, weight='bold')
    plt.ylabel('Pico de CPU (%)', fontsize=12)
    plt.xlabel('Intensidade do Ataque', fontsize=12)
    plt.ylim(0, 110)

    # Linha de Morte
    plt.axhline(100, color='red', linestyle='--', linewidth=2, label='Limite de Crash (100%)')

    plt.tight_layout()
    plt.savefig('grafico_impacto_fisico.png', dpi=300)
    print("Mostrando gráfico de Impacto Físico... (Feche a janela para ver o próximo)")
    plt.show()
    print("Gráfico guardado como 'grafico_impacto_fisico.png'")


def plot_mitigation_speed(df):
    """Gera e mostra o gráfico de Velocidade de Mitigação (Tempo de Resposta)."""
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(10, 6))

    # Obter as intensidades exatas para o eixo X
    unique_intensities = sorted(df['Scenario_Intensity'].unique())

    # Gráfico de linha com intervalo de confiança
    sns.lineplot(
        x='Scenario_Intensity',
        y='Response_Time',
        data=df,
        marker='s',
        color='purple',
        linewidth=2.5,
        errorbar=('ci', 95)  # Intervalo de confiança de 95%
    )

    plt.title('Velocidade de Mitigação (Time-to-Mitigation)', fontsize=16, weight='bold')
    plt.ylabel('Tempo (Segundos)', fontsize=12)
    plt.xlabel('Intensidade do Ataque', fontsize=12)

    # Forçar eixo X para mostrar apenas as intensidades reais
    plt.xticks(unique_intensities)

    plt.tight_layout()
    plt.savefig('grafico_velocidade_mitigacao.png', dpi=300)
    print("Mostrando gráfico de Velocidade de Mitigação...")
    plt.show()
    print("Gráfico guardado como 'grafico_velocidade_mitigacao.png'")


# Executar
if __name__ == "__main__":
    df = load_and_clean_data('../simulation_metrics_cpu.csv')
    if df is not None:
        plot_physical_impact(df)
        plot_mitigation_speed(df)