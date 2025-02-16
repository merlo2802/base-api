package com.cursos.api.springsecuritycourse.controller;

import com.cursos.api.springsecuritycourse.dto.SavePermission;
import com.cursos.api.springsecuritycourse.dto.ShowPermission;
import com.cursos.api.springsecuritycourse.service.PermissionService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/permissions")
public class PermissionController {

    @Autowired
    private PermissionService permissionService;

    @GetMapping
    public ResponseEntity<Page<ShowPermission>> findAll(Pageable pageable){

        Page<ShowPermission> permissions = permissionService.findAll(pageable);

        if(permissions.hasContent()){
            return ResponseEntity.ok(permissions);
        }

        return ResponseEntity.notFound().build();
    }

    @GetMapping("/{permissionId}")
    public ResponseEntity<ShowPermission> findOneById(@PathVariable Long permissionId){
        Optional<ShowPermission> permission = permissionService.findOneById(permissionId);

        if(permission.isPresent()){
            return ResponseEntity.ok(permission.get());
        }

        return ResponseEntity.notFound().build();
    }

    @PostMapping
    public ResponseEntity<ShowPermission> createOne(@RequestBody @Valid SavePermission savePermission){
        ShowPermission permission = permissionService.createOne(savePermission);
        return ResponseEntity.status(HttpStatus.CREATED).body(permission);
    }

    @DeleteMapping("/{permissionId}")
    public ResponseEntity<ShowPermission> deleteOneById(@PathVariable Long permissionId){
        ShowPermission permission = permissionService.deleteOneById(permissionId);
        return ResponseEntity.ok(permission);
    }

}
