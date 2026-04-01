// settings.js — reads and writes extension settings via browser.storage.local

const Settings = {
  async getApiKey() {
    return new Promise(resolve => {
      browser.storage.local.get("vtApiKey", result => {
        resolve(result.vtApiKey || null);
      });
    });
  },

  async setApiKey(key) {
    return new Promise(resolve => {
      browser.storage.local.set({ vtApiKey: key }, resolve);
    });
  },

  async clearApiKey() {
    return new Promise(resolve => {
      browser.storage.local.remove("vtApiKey", resolve);
    });
  }
};
