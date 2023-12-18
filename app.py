import pipeline as pl
import streamlit as st
import pandas as pd

st.title("Pipeline")

logs = st.text_area("Log", height=200, value="")
lines = logs.split('\n')

if st.button("Run"):
    df = pd.DataFrame(pl.parse_log(log) for log in lines)
    df = pl.clean_data(df)
    binclf = pl.load_model('raksha_v3.0.pkl')
    pred = pl.detect(binclf, df)
    mltclf = pl.load_classifier('raksha_ultra_xlf.pkl')
    indices = pl.get_threats(pred, lines)
    df = pl.classify(mltclf, df, indices)
    st.write("Detected {} threats out of {} logs.".format(len(pred), len(lines)))
    df = list(pd.Series(df).value_counts())
    for count in df:
        st.write(f'Level {df.index(count)+1} threats: {count}')