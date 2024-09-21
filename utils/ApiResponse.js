//utils/ApiResponse.js

class ApiResponse {
    constructor(success, message, data = null, statusCode = 200) {
      this.success = success;
      this.message = message;
      this.data = data;
      this.statusCode = statusCode;
    }
  
    send(res) {
      return res.status(this.statusCode).json({
        success: this.success,
        message: this.message,
        data: this.data
      });
    }
  
    static success(message, data = null, statusCode = 200) {
      return new ApiResponse(true, message, data, statusCode);
    }
  
    static error(message, statusCode = 400, data = null) {
      return new ApiResponse(false, message, data, statusCode);
    }
  }
  
  module.exports = ApiResponse;