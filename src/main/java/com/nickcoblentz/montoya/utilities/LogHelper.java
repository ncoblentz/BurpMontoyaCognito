package com.nickcoblentz.montoya.utilities;

import burp.api.montoya.MontoyaApi;

public class LogHelper {

    private static LogHelper _instance;
    private LogLevel _level;
    private MontoyaApi _api;

    public enum LogLevel
    {
        DEBUG,
        INFO,
        ERROR
    }

    private LogHelper(MontoyaApi api)
    {
        _api = api;
        _level=LogLevel.INFO;

    }

    public static LogHelper GetInstance(MontoyaApi api)
    {
        if(_instance==null) {
            _instance = new LogHelper(api);
        }
        return _instance;
    }
    
    public void SetLevel(LogLevel level)
    {
        _level = level;
    }

    public void Debug(String message)
    {
        if(_level.equals(LogLevel.DEBUG))
        {
            _api.logging().logToOutput(message);
        }
    }

    public void Info(String message)
    {
        if(_level.equals(LogLevel.DEBUG) || _level.equals(LogLevel.INFO))
        {
            _api.logging().logToOutput(message);
        }
    }

    public void Error(String message)
    {
        if(_level.equals(LogLevel.DEBUG) || _level.equals(LogLevel.INFO) || _level.equals(LogLevel.ERROR))
        {
            _api.logging().logToOutput(message);
        }
    }
}
