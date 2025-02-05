'use strict';

const Homey = require('homey');
const http = require('http.min');

class ThermostatDriver extends Homey.Driver {
  onPair(socket) {
    socket.on('login', async (data, callback) => {
      const email = data.username;
      const password = data.password;

      Homey.ManagerSettings.set('username', email);
      Homey.ManagerSettings.set('password', password);

      try {
        const token = await getResideoToken(email, password);
        Homey.ManagerSettings.set('access_token', token.access_token);
        Homey.ManagerSettings.set('refresh_token', token.refresh_token);
        callback(null, true);
      } catch (error) {
        console.error('Login failed:', error);
        callback('Login failed');
      }
    });

    socket.on('list_devices', async (data, callback) => {
      try {
        const devices = await listResideoDevices();
        callback(null, devices);
      } catch (error) {
        callback(error.message || error.toString());
      }
    });
  }
}

module.exports = ThermostatDriver;






async function refreshResideoToken() {
  const clientId = "YOUR_CLIENT_ID";
  const clientSecret = "YOUR_CLIENT_SECRET";
  const refreshToken = Homey.ManagerSettings.get('refresh_token');

  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  const response = await http.post("https://api.honeywell.com/oauth2/token", {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + Buffer.from(clientId + ':' + clientSecret).toString('base64')
    },
    form: {
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    }
  });

  if (!response.data || !response.data.access_token) {
    throw new Error('Failed to refresh token');
  }

  Homey.ManagerSettings.set('access_token', response.data.access_token);
  Homey.ManagerSettings.set('refresh_token', response.data.refresh_token);
  
  return response.data.access_token;
}



async function listResideoDevices() {
  let accessToken = Homey.ManagerSettings.get('access_token');

  try {
    const locationResponse = await http.get("https://api.honeywell.com/v2/locations", {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });

    const locationId = locationResponse.data[0]?.locationID;
    if (!locationId) throw new Error('No location ID found');

    const deviceResponse = await http.get(`https://api.honeywell.com/v2/devices?locationId=${locationId}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });

    if (!deviceResponse.data || deviceResponse.data.length === 0) {
      throw new Error('No devices found');
    }

    return deviceResponse.data.map(device => ({
      name: device.deviceName || device.userDefinedDeviceName,
      data: {
        id: device.deviceID,
        location: locationId
      }
    }));

  } catch (error) {
    if (error.message.includes("401")) {
      console.log("Access token expired, refreshing...");
      accessToken = await refreshResideoToken();
      return listResideoDevices(); // Retry after refreshing token
    }
    throw error;
  }
}
