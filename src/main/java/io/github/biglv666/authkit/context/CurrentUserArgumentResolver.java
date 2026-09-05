package io.github.biglv666.authkit.context;

import io.github.biglv666.authkit.annotation.CurrentUser;
import io.github.biglv666.authkit.core.AuthContext;
import io.github.biglv666.authkit.exception.NotLoginException;
import io.github.biglv666.authkit.exception.NotLoginReason;
import io.github.biglv666.authkit.model.AuthUser;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * {@code @CurrentUser} 参数解析器：将当前登录用户注入 Controller 方法参数。
 * <p>仅支持 AuthUser 类型参数；required=true 且未登录时抛 NotLoginException。</p>
 */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && AuthUser.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        CurrentUser annotation = parameter.getParameterAnnotation(CurrentUser.class);
        String userId = AuthContext.getUserId();
        if (userId == null) {
            if (annotation == null || annotation.required()) {
                throw new NotLoginException(NotLoginReason.NO_TOKEN);
            }
            return null;
        }
        return new AuthUser(userId, AuthContext.getDevice(), AuthContext.getToken());
    }
}
