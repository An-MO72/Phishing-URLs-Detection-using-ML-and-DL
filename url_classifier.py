from urllib.parse import urlparse
import streamlit as st
from features_extraction import DETECTION
import pickle
import numpy as np
import whois

def main():
    st.title("Vérificateur d'URL malveillantes")
    st.write("Entrez une URL pour vérifier si elle est malveillante ou non :")

    # URL input and check button
    url = st.text_input("URL:")
    if st.button("Check"):
        if not url:
            st.warning("Please enter a URL.")
        else:
        # Performing URL check
            detection = DETECTION()
            # extracting features
            features = detection.featureExtractions(url)

            # Load the trained model
            with open('Multilayer_perceptrons.pickle.dat', 'rb') as f:
                model = pickle.load(f)
            input_data = np.array(features).reshape(1, -1)
            # Make prediction
            prediction = model.predict(input_data)
            
            # diplay prediction
            if prediction:
                st.error("L'URL est malveillante.")
            else:
                st.success("L'URL est légitime ")


if __name__ == "__main__":
    main()
