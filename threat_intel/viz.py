import pandas as pd
import altair as alt
from pyvis.network import Network


def chart_daily_counts(df: pd.DataFrame):
    if df.empty:
        return alt.Chart(pd.DataFrame({"date": [], "count": []})).mark_bar()
    dd = df.copy()
    dd["day"] = dd["published_at"].str[:10].replace("", None)
    dd["day"] = dd["day"].fillna(pd.Timestamp.utcnow().strftime("%Y-%m-%d"))
    agg = dd.groupby("day").size().reset_index(name="count")
    chart = (
        alt.Chart(agg)
        .mark_area(line=True)
        .encode(x="day:T", y="count:Q")
        .properties(height=220)
    )
    return chart


def chart_category_distribution(df: pd.DataFrame):
    if df.empty:
        return alt.Chart(pd.DataFrame({"label": [], "count": []})).mark_bar()
    labels = []
    for _, row in df.iterrows():
        s = (row.get("summary") or "").lower()
        found = []
        for l in ["malware", "ransomware", "phishing", "vulnerability", "data breach"]:
            if l in s:
                found.append(l.title())
        labels.append(", ".join(found) if found else "Other")
    dd = pd.DataFrame({"label": labels})
    agg = dd.value_counts().reset_index(name="count")
    agg.columns = ["label", "count"]
    chart = (
        alt.Chart(agg)
        .mark_bar()
        .encode(x="label:N", y="count:Q", tooltip=["label", "count"])
        .properties(height=220)
    )
    return chart


def chart_top_indicators(ioc_df: pd.DataFrame):
    if ioc_df is None or ioc_df.empty:
        return alt.Chart(pd.DataFrame({"value": [], "count": []})).mark_bar()
    dd = ioc_df.copy()
    dd["key"] = dd["type"].str.upper() + ": " + dd["value"]
    agg = dd.groupby("key").size().reset_index(name="count").sort_values("count", ascending=False).head(20)
    chart = (
        alt.Chart(agg)
        .mark_bar()
        .encode(y=alt.Y("key:N", sort="-x"), x="count:Q", tooltip=["key", "count"])
        .properties(height=400)
    )
    return chart


def render_ioc_network_html(items_df: pd.DataFrame, ioc_df: pd.DataFrame) -> str:
    net = Network(height="520px", width="100%", bgcolor="#111111", font_color="white", notebook=False, directed=False)
    net.toggle_physics(True)

    for _, row in items_df.iterrows():
        nid = f"item:{row['id']}"
        label = (row.get("title") or "")[:60]
        net.add_node(nid, label=label, shape="box", color="#6c8ebf", title=row.get("url") or "")

    if ioc_df is not None and not ioc_df.empty:
        for _, r in ioc_df.iterrows():
            item_id = r["item_id"]
            nid_item = f"item:{item_id}"
            n_ioc = f"{r['type']}:{r['value']}"
            color = "#8fbf6c" if r["type"] in ("domain", "url") else "#bf6c8f"
            net.add_node(n_ioc, label=n_ioc, shape="dot", color=color)
            net.add_edge(nid_item, n_ioc, color="#888888")

    html = net.generate_html(notebook=False)
    return html
