package com.example.backend.dto;

public record TokenResponse(String accessToken, long expiresInSeconds) {}