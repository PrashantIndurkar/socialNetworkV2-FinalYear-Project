import axios from "axios";

const setAuthToken = token => {
  //if there is already a token in the localstorage, we just send it with every request
  //instead of picking and choosing which request to send it with
  if (token) {
    axios.defaults.headers.common["x-auth-token"] = token;
  } else {
    delete axios.defaults.headers.common["x-auth-token"];
  }
};

export default setAuthToken;
