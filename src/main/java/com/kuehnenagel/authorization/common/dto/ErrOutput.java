package com.kuehnenagel.authorization.common.dto;

import java.io.Serial;
import java.io.Serializable;

public record ErrOutput(boolean success, String errCode, String errMessage) implements Serializable {
    @Serial
    private static final long serialVersionUID = 7815127066080050818L;
}
