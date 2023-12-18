import pipeline as pl
import streamlit as st
import pandas as pd

st.title("Detect Log Threats")

logs = st.text_area("Log", height=200, value="")
lines = logs.split('\n')

if st.button("Run"):
    df = pd.DataFrame(pl.parse_log(log) for log in lines)
    df = pl.clean_data(df)
    binclf = pl.load_model('raksha_v3.0.pkl')
    pred = pl.detect(binclf, df)
    mltclf = pl.load_classifier('raksha_ultra_xlf.pkl')
    indices = pl.get_threats(pred, lines)
    st.write("Detected {} threats out of {} logs.".format(sum(pred), len(lines)))
    if indices == []:
        st.write("No threats detected.")
    else:
        df = pl.classify(mltclf, df, indices)
        df = dict(pd.Series(df).value_counts())
        for key in df.keys():
            st.write(f'Level {key+1} threats: {df[key]}')
