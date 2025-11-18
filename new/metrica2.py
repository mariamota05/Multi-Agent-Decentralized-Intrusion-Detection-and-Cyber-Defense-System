import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_and_clean_data(filename):
    df = pd.read_csv(filename)
    # Garantir que são números inteiros
    df['Raw_Leakage_Count'] = df['Raw_Leakage_Count'].astype(int)
    df['Raw_Overload_Cycles'] = df['Raw_Overload_Cycles'].astype(int)
    df['Scenario_Intensity'] = df['Scenario_Intensity'].astype(int)
    return df


def plot_correlation(df):
    # Configurar estilo
    sns.set_theme(style="whitegrid", context="talk")
    plt.figure(figsize=(10, 8))

    # Scatter plot: Cada ponto é um teste que você fez
    sns.scatterplot(
        data=df,
        x='Raw_Leakage_Count',
        y='Raw_Overload_Cycles',
        hue='Scenario_Intensity',  # As cores mostram a "força" do ataque
        palette='viridis',
        size='Scenario_Intensity',  # O tamanho dos pontos também mostra a "força
        s=200,  # Tamanho dos pontos
        edgecolor='black',
        alpha=0.8
    )

    # Adicionar uma linha de tendência para mostrar a correlação
    # (Mostra que quanto mais leakage, mais overload)
    sns.regplot(
        data=df,
        x='Raw_Leakage_Count',
        y='Raw_Overload_Cycles',
        scatter=False,
        color='grey',
        line_kws={"linestyle": "--", "linewidth": 1.5}
    )

    # Títulos e Etiquetas
    plt.title('Análise de Impacto: Fuga vs. Sobrecarga', fontsize=18, weight='bold', pad=20)
    plt.xlabel('Mensagens que "furaram" a defesa (Leakage)', fontsize=14)
    plt.ylabel('Tempo de Sofrimento do Nó (Ciclos > 90% CPU)', fontsize=14)
    plt.legend(title='Intensidade', bbox_to_anchor=(1.05, 1), loc='upper left')

    # Adicionar anotações explicativas (opcional)
    plt.text(0.5, -0.15, "Conclusão: Pequenas fugas em alta intensidade causam grande sobrecarga.",
             transform=plt.gca().transAxes, ha='center', fontsize=12, style='italic')

    plt.tight_layout()
    plt.savefig('grafico_correlacao.png', dpi=300)
    plt.show()
    print("Gráfico guardado como 'grafico_correlacao.png'")


if __name__ == "__main__":
    try:
        df = load_and_clean_data('simulation_metrics_cpu.csv')
        plot_correlation(df)
    except FileNotFoundError:
        print("Erro: Ficheiro 'simulation_metrics.csv' não encontrado.")