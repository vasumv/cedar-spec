import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import utils
from scipy import stats
import json

def plot_uniqueness(df, columns, generators, savefile=None, title='Uniqueness Plots'):
    # Create a figure and axis object
    fig, axes = plt.subplots(nrows=1, ncols=len(generators), figsize=(3 * len(generators), 3), sharey=True)
    df["overall"] = df["representation"]
    df = df.drop(columns=["representation"])
    # Set custom colors for the bars
    unique_color = 'navy'
    reference_color = 'skyblue'
    df_copy = df.copy()
    # Loop through the generators
    for i, generator in enumerate(generators):
        # Loop through the specified columns
        df = df_copy.copy()
        df = df[df["generator"] == generator]
        unique_percentages = []
        for col in columns:
            if df[col].apply(lambda x: isinstance(x, dict) or isinstance(x, list)).any():
                df[col] = df[col].apply(lambda x: str(x))
            # Count the unique values
            unique_count = df[col].nunique()
            # Count the total values
            total_count = len(df[col])
            # Calculate the unique percentage
            unique_pct = unique_count / total_count * 100
            unique_percentages.append(unique_pct)

        # Create the bar plot
        bar_plot = axes[i].bar(columns, unique_percentages, color=unique_color, alpha=0.7, width=0.6)

        # Add 100% bars for reference
        axes[i].bar(columns, [100] * len(columns), color=reference_color, alpha=0.4, width=0.6)

        # Add values to the bars
        for bar in bar_plot:
            height = bar.get_height()
            axes[i].annotate(
                f"{height:.2f}%",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8
            )

        # Add labels and title
        axes[i].set_xlabel('Input Feature', fontsize=12)
        axes[i].set_title(f'{generator}', fontsize=12, y=1.05)

        # Rotate the x-axis labels for better visibility
        plt.sca(axes[i])
        plt.xticks(rotation=45)

        # Set y-axis limits
        axes[i].set_ylim(0, 100)

    # Add a common y-axis label
    fig.text(0.04, 0.5, 'Percentage', va='center', rotation='vertical', fontsize=12)

    # Add a title for the entire plot
    fig.suptitle(title, fontsize=18, y=1.1)

    # Adjust layout
    plt.subplots_adjust(wspace=0.2)

    # Add a legend
    unique_patch = plt.Rectangle((0, 0), 1, 1, fc=unique_color, alpha=0.7, edgecolor='none')
    reference_patch = plt.Rectangle((0, 0), 1, 1, fc=reference_color, alpha=0.4, edgecolor='none')
    fig.legend([unique_patch], ['Unique'], loc='upper left', bbox_to_anchor=(0.11, 0.9))

    if savefile:
        plt.savefig(savefile, bbox_inches='tight')

    # Show the plot
    plt.show()


def plot_validity_over_time(df, target, column='Validity', feature="Unique Expressions", savefile=None):
    if "Unique" in column:
        df["Percent Unique"] = df[feature] / df["Total"] * 100
    # Filter configurations with and without "Random"
    # configs_1 = df[(df["Target"] == target) & df["Configuration"].str.contains("Derived")]["Configuration"].unique()
    configs_2 = df[(df["Target"] == target) & df["Configuration"].str.contains("fail-fast")]["Configuration"].unique()
    configs_3 = df[(df["Target"] == target) & df["Configuration"].str.contains("fail-fix")]["Configuration"].unique()
    print(configs_2, configs_3)
    # Create a figure with two subplots
    fig, ax2 = plt.subplots(1, 1, figsize=(6, 4), sharey=True)

    # Plot configurations with "Random"
    # sns.lineplot(data=df[(df["Target"] == target) & df["Configuration"].isin(configs_1)],
    #              x='Checkpoint', y=column, hue='Configuration', ax=ax1, dashes=True)
    # ax1.set_title("Derived Generator")
    # ax1.set_xlabel("")
    # ax1.set_ylabel("")
    # ax1.set_ylim(0, 100)
    # ax1.legend(bbox_to_anchor=(0, 1), loc='upper left')

    # Plot configurations without "Random"
    sns.lineplot(data=df[(df["Target"] == target) & df["Configuration"].isin(configs_2)],
                 x='Checkpoint', y=column, hue='Configuration', ax=ax2)
    ax2.set_title("Hand-Written Generator (fail-fast)")
    ax2.set_xlabel("")
    ax2.set_ylabel("")
    # ax2.legend(loc='center')

    # # Plot configurations without "Random"
    # sns.lineplot(data=df[(df["Target"] == target) & df["Configuration"].isin(configs_3)],
    #              x='Checkpoint', y=column, hue='Configuration', ax=ax3)
    # ax3.set_title("Hand-Written Generator (fail-fix)")
    # ax3.set_xlabel("")
    # ax3.set_ylabel("")
    # ax3.legend(loc='center', bbox_to_anchor=(0, 0.3))


    # Set the axis labels and title
    fig.text(0.5, -0.01, 'Hour', ha='center', fontsize=14)
    fig.text(0.0, 0.5, f'{column}', va='center', rotation='vertical', fontsize=14)
    fig.suptitle(f'{feature} Over Time: Authorizer', fontsize=16, y=1.05)

    # Adjust layout
    plt.subplots_adjust(wspace=0.2)
    if savefile:
        plt.savefig(savefile, bbox_inches='tight')
    # Show the plot
    plt.show()

def plot_est_node_dist(df, generator='Derived', savefig=None):
    # Step 1: Apply the get_category_map function
    category_maps = df[df['generator'] == generator]['expression'].apply(lambda x: utils.get_category_map(json.loads(x)))

    # Step 2: Create a new DataFrame from the Series
    category_freqs_df = pd.DataFrame(category_maps.tolist())
    category_freqs_df = category_freqs_df.fillna(0)

    # Step 3: Calculate the mean of each column (category) across all rows
    category_mean_freqs = category_freqs_df.mean(axis=0)

    # Step 4: Normalize frequencies
    category_mean_freqs = category_mean_freqs / category_mean_freqs.sum()

    # Step 5: Sort by decreasing value
    category_mean_freqs = category_mean_freqs.sort_values(ascending=False)
    # Step 6: Create a histogram
    plt.figure(figsize=(6, 4))
    sns.barplot(x=category_mean_freqs.index, y=category_mean_freqs.values)
    plt.xticks(rotation=90)
    plt.xlabel('Node Kind', fontsize=16)
    plt.ylabel('Normalized Frequency', fontsize=16)
    plt.title(f'Node Kind Distribution: \n{generator}', fontsize=20)
    plt.ylim(0, 1)
    entropy = stats.entropy(category_mean_freqs.values)
    plt.text(20, 0.85, f'Entropy: {entropy:.2f}', fontsize=16)
    if savefig:
        plt.savefig(savefig, bbox_inches='tight')
    plt.show()
